%%%===================================================================
%%% @copyright (C) 2025, IQOM R&D.
%%% @doc Module abstracting Websockets over TCP connection to JSON server
%%% @end
%%%===================================================================

-module(eims_ws_client).
-behaviour(gen_server).
-compile(export_all).

-include("logger.hrl").
-include("eims.hrl").
-include_lib("xmpp/include/xmpp.hrl").
-include_lib("htmerl/include/htmerl.hrl").

%% API exports
-export([connect/1,
	start_link/0,
	start_link/1,
	send/1,
	send/2,
	stop/0,
	kill/0]).

%% gen_server callbacks
-export([init/1,
	handle_call/3,
	handle_cast/2,
	handle_info/2,
	terminate/2,
	code_change/3]).

-define(SERVER, ?MODULE).
-define(INTERVAL, 10).
-define(TIMEOUT_INTERVAL, ?INTERVAL).
-define(RECONNECT_INTERVAL, 3000).
-define(HEARTBEAT_INTERVAL, ?INTERVAL * 1000 + 100).
-define(HEARTBEAT_ID, 1).

-record(state, {owner, socket, stream_ref = [], label_map = #{}, options = [], heartbeat = erlang:system_time(millisecond), reconnect_ref = [],
				heartbeat_ref = [], ids = #{}, callback = {eims, broadcast_from_bot}, down_msg = ?UNAVAILABLE_MSG}).
-type state() :: #state{}.

%%%===================================================================
%%% API
%%%===================================================================
start_link(Args) ->
	WsOpts = [{K, gen_mod:get_module_opt(global, mod_eims_admin, V)} || {K, V} <- [{port, ws_port}, {resource, ws_resource}]],
	connect([{host, eims:hservice_host()}, {ssl, true}] ++ WsOpts ++ Args).
start_link() ->
	start_link([]).

-spec connect([proplists:property()]) -> pid() | {error, {already_started, pid()}}.
connect(Args) ->
	gen_server:start_link({local, ?SERVER}, ?MODULE, [Args, self()], []).

-spec send(binary()) -> ok.
send(Data) ->
	gen_server:cast(?MODULE, {send, Data}).

-spec get_state() -> #state{}.
get_state() ->
	call(state).

fake_send(#{} = Data) ->
	{#state{stream_ref = StreamRef, socket = ConnPid}, Pid} = get_state(),
	Pid ! {gun_ws, ConnPid, StreamRef, {text, jiffy:encode(Data)}};
fake_send(Data) ->
	fake_send(jiffy:decode(Data, [return_maps])).

-spec send(binary(), function()) -> ok.
send(Data, Fun) ->
	gen_server:cast(?MODULE, {send, Data, Fun}).

hb_interval() -> ?HEARTBEAT_INTERVAL.
timeout_interval() -> ?TIMEOUT_INTERVAL * 1000.
reconnect_interval() -> ?RECONNECT_INTERVAL.

is_timeout(Time, Interval) -> erlang:system_time(millisecond) - Time > Interval.
is_timeout(Time) ->	is_timeout(Time, ?INTERVAL * 1000).

set_heartbeat(Interval) ->
	Pid = self(),
	send(msg(<<"public/set_heartbeat">>, #{<<"interval">> => Interval}, ?HEARTBEAT_ID),
			fun(#{<<"id">> := ?HEARTBEAT_ID}) -> Pid ! heartbeat end).

-spec stop() -> ok | already_stopped.
stop() ->
	try
		call(stop)
	catch
		exit:{noproc, {gen_server, call, _}} ->
			already_stopped;
		exit:{normal, {gen_server, call, _}} ->
			already_stopped
	end.

-spec kill() -> ok | already_stopped.
kill() ->
	%% Use `kill_connection` to avoid confusion with exit reason `kill`.
	try
		call(kill_connection)
	catch
		exit:{noproc, {gen_server, call, _}} ->
			already_stopped;
		exit:{normal, {gen_server, call, _}} ->
			already_stopped
	end.

msg(Method, Params, Id) when is_integer(Id) ->
	(msg(Method, Params))#{<<"id">> => Id}.
msg(Method, #{} = Params) ->
	#{<<"jsonrpc">> => <<"2.0">>, <<"method">> => Method, <<"params">> => Params}.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% TODO: refactor all opt defaults taken from Args into a default_opts function,
%%       so that we know what options the module actually expects
-spec init(list()) -> {ok, state()}.
init([Args, Owner] = Opts) ->
	Host = get_host(Args, "localhost"),
	Port = get_port(Args, 80),
	Resource = get_resource(Args, "/ws/api/v2"),
	SSL = proplists:get_value(ssl, Args, false),
	SSLOpts = proplists:get_value(ssl_opts, Args, []),
	%% Disable http2 in protocols
	TransportOpts =
		case SSL of
			true ->
				#{protocols => [http], retry => 10, transport => ssl, tls_opts => SSLOpts};
			_ ->
				#{transport => tcp, protocols => [http]}
		end,
	{ok, ConnPid} = gun:open(Host, Port, TransportOpts),
	Callback = proplists:get_value(callback, Args, {eims, broadcast_from_bot}),
	State = #state{owner = Owner, options = Opts, socket = ConnPid, callback = Callback},
	case gun:await_up(ConnPid) of
		{ok, http} ->
			WSUpgradeHeaders = [{<<"sec-websocket-protocol">>, <<"json">>}],

			StreamRef = gun:ws_upgrade(ConnPid, Resource, WSUpgradeHeaders),
			Timeout = get_option(ws_upgrade_timeout, Args, 10000),
			{TReconRef, DownMsg} =
				case ?MODULE:wait_for_ws_upgrade(ConnPid, StreamRef, Timeout) of
					ok ->
						?dbg("WS: START", []),
						set_heartbeat(?INTERVAL),
						{[], ?UNAVAILABLE_MSG}; %% TODO refactor in future
					{ws_upgrade_failed, UpFailedMsg} ->
						{reconnection_timer(ConnPid), UpFailedMsg};
					{ws_upgrade_failed, Err, _} ->
						?err("WS UPGRADE FAILED: ~p", [Err]),
						{reconnection_timer(ConnPid), ?UNAVAILABLE_MSG}
				end,
			{ok, State#state{stream_ref = StreamRef, reconnect_ref = TReconRef, down_msg = DownMsg}};
		{error, Reason} ->
			?err("WS: AWAIT UP FAILED: REASON: ~p", [Reason]),
			{ok, State#state{reconnect_ref = reconnection_timer(ConnPid)}}
	end.

-spec reconnection_timer(Pid::pid()) -> reference().
reconnection_timer(Pid) ->
	gun:close(Pid),
	{ok, TRef} = timer:apply_after(reconnect_interval(), ?MODULE, reconnect, []), TRef.

wait_for_ws_upgrade(ConnPid, StreamRef, Timeout) ->
	receive
		{gun_upgrade, ConnPid, StreamRef, [<<"websocket">>], _} ->
			ok;
		{gun_response, ConnPid, _, _, Status, Headers} ->
			?err("WS: UPGRADE FAILED: STATUS = ~p: HEADERS = ~p", [Status, Headers]),
			receive
				{gun_data, ConnPid, _, nofin, Data} ->
					?err("WS: MAINTANANCE: ~p", [Data]),
					ws_upgrade_failed(Data);
				{gun_data, ConnPid, _, fin, Data} ->
					?err("WS: MAINTANANCE: ~p", [Data]),
					ws_upgrade_failed();
				GunMsg ->
					?err("WS: UNEXPECTED MAINTENENCE: ~p", [GunMsg]),
					ws_upgrade_failed()
			after
				Timeout ->
					?err("WS: MAINTANANCE: TIMEOUT"),
					ws_upgrade_failed()
			end;
		{gun_error, ConnPid, _StreamRef, Reason} ->
			?err("WS: UPGRADE FAILED: STATUS = ~p: REASON = ~p", [Reason]),
			ws_upgrade_failed()
	after %% More clauses here as needed.
		Timeout ->
			?err("WS: UPGRADE TIMEOUT"),
			ws_upgrade_failed()
	end.

ws_upgrade_failed() ->
	{ws_upgrade_failed, ?UNAVAILABLE_MSG}.
ws_upgrade_failed(Html) -> %% get down message from received html
	PredFun =
		fun(#htmlElement{attributes = [#htmlAttribute{name = <<"class">>, value = <<"error-subtitle">>}]}) -> true;
			(_) -> false
		end,
	case catch eims:find_html_el(htmerl:simple(Html), PredFun) of
		#htmlElement{content = [#htmlText{value = Text}]} ->
			{ws_upgrade_failed, Text};
		false ->
			?err("WS: MAINTANANCE: UP MESSAGE NOT FOUND: ~p", [Html]),
			ws_upgrade_failed();
		Err ->
			?err("WS: MAINTANANCE: INVALID HTML: ~p, ~p", [Err, Html]),
			ws_upgrade_failed()
	end.

-spec handle_call(term(), {pid(), term()}, state()) ->
	{reply, term(), state()} | {stop, normal, ok, state()}.
handle_call(labels, _From, #state{label_map = LabelMap} = State) ->
	{reply, LabelMap, State};
handle_call({remove_label, Label}, _From, #state{label_map = LabelMap} = State) ->
	NewState = State#state{label_map = NewLabelMap = maps:remove(Label, LabelMap)},
	{reply, NewLabelMap, NewState};
handle_call({get_label, Label}, _From, #state{label_map = LabelMap} = State) ->
	Data2 = case LabelMap of #{Label := Data} -> Data; _ -> {error, not_found} end,
	{reply, Data2, State};
handle_call(purge_labels, _From, #state{} = State) ->
	NewState = State#state{label_map = #{}},
	{reply, #{}, NewState};
handle_call({add_label, {Label, Data}}, _From, #state{label_map = LabelMap} = State) ->
	NewState = State#state{label_map = NewLabelMap = LabelMap#{Label => Data}},
	{reply, NewLabelMap, NewState};
handle_call(state, _, S) ->
	{reply, {S, self()}, S};
handle_call(kill_connection, _, S) ->
	{stop, normal, ok, S};
handle_call(stop, _From, #state{socket = ConnPid, stream_ref = StreamRef} = State) ->
	gun:ws_send(ConnPid, StreamRef, close),
	{stop, normal, ok, State}.

-spec handle_cast(term(), state()) -> {noreply, state()}.
handle_cast({send, #{<<"params">> := #{<<"label">> := Label}} = Data, SendFun},
	#state{label_map = Labels} = State) ->
	Id = erlang:phash2(Label),
	?dbg("WS: SEND: ~p, id = ~p", [Data, Id]),
	handle_cast({send, jiffy:encode(Data)},
		State#state{label_map = Labels#{Id => SendFun}, ids = #{Id => erlang:system_time(millisecond)}});
handle_cast({send, #{<<"id">> := Id} = Data, SendFun},
	#state{label_map = Labels} = State) ->
	?dbg("WS: SEND: ~p, id = ~p", [Data, Id]),
	handle_cast({send, jiffy:encode(Data)},
		State#state{label_map = Labels#{Id => SendFun},
					ids = #{Id => erlang:system_time(millisecond)}});
handle_cast({send, #{} = Data}, #state{} = State) ->
	?dbg("WS: SEND: ~p", [Data]),
	handle_cast({send, jiffy:encode(Data)}, State);
handle_cast({send, Data}, #state{socket = Socket, stream_ref = Stream, heartbeat = Heartbeat, reconnect_ref = []} = State) ->
	case is_timeout(Heartbeat) of
		true ->
			?dbg("WS SEND: Expired heartbeat: Reconnect: ~p", [erlang:system_time(millisecond) - Heartbeat]),
			handle_info(reconnect, State);
		_ ->
			case catch gun:ws_send(Socket, Stream, {text, Data}) of
				ok -> {noreply, State};
				Err ->
					?dbg("WS SEND: Connection failed: Reconnect: ~p", [Err]),
					handle_info(reconnect, State)
			end
	end;
handle_cast({send, Data}, #state{} = State) ->
	case catch jiffy:decode(Data, [return_maps]) of
		#{<<"id">> := Id} = Map->
			?dbg("WS: SERVER UNAVAILABLE: ~p", [Map]),
			handle_data(#{<<"id">> => Id, <<"error">> => <<"Integrated service unavailable. Try later.">>}, State);
		#{} = Map ->
			?dbg("WS: SERVER UNAVAILABLE: ~p", [Map]),
			State;
		_ ->
			?dbg("WS: SERVER UNAVAILABLE: ~p", [Data]),
			State
	end.


-spec handle_info(term(), state()) -> {noreply, state()} | {stop, term(), state()}.
handle_info(heartbeat, #state{heartbeat = Heartbeat, heartbeat_ref = Ref} = State) ->
	?dbg("WS: INTERNAL HEARTBEAT", []),
	HBTRef = case is_timeout(Heartbeat) of
		        true -> handle_info(reconnect, State), [];
		        _ -> timer:cancel(Ref),
			        {ok, TRef} = timer:send_after(?MODULE:hb_interval(), self(), heartbeat),
			        TRef
	        end,
	{noreply, send_timeout(State#state{heartbeat_ref = HBTRef})};
handle_info(reconnect, #state{options = Opts, label_map = Labels, socket = ConnPid,
	heartbeat_ref = HBTRef, reconnect_ref = TRef, ids = Ids, callback = {M, F}} = State) ->
	?dbg("WS: RECONNECT", []),
	gun:close(ConnPid),
	[timer:cancel(Ref) || Ref <- [HBTRef, TRef]],
	State2 =
		case catch init(Opts) of
			{ok, #state{reconnect_ref = TReconRef, down_msg = DownMsg} = NewState} ->
				case {TRef, TReconRef} of {[], []} -> ok; {[], _} -> M:F(DownMsg); {_, []} -> M:F(?AVAILABLE_MSG); _ -> ok end,
				NewState#state{label_map = Labels, ids = Ids};
			Err ->
				?dbg("WS RECONNECT: FAILED: ~p", [Err]),
				{ok, NewTRef} = timer:apply_after(reconnect_interval(), ?MODULE, reconnect, []),
				State#state{reconnect_ref = NewTRef}
		end,
	{noreply, send_timeout(State2#state{heartbeat_ref = []})};
handle_info(tcp_closed, State) ->
	?dbg("WS: tcp_closed", []),
	{stop, normal, State};
handle_info({error, Reason}, State) ->
	?dbg("WS: error: ~p", [Reason]),
	{stop, Reason, State};
handle_info({gun_ws, ConnPid, _StreamRef, close} = Data, #state{socket = ConnPid} = State) ->
	?dbg("WS close: ~p", [Data]),
	{stop, normal, State};
handle_info({gun_ws, ConnPid, _StreamRef, {close, _}} = Data, #state{socket = ConnPid} = State) ->
	?dbg("WS close: ~p", [Data]),
	{stop, normal, State};
handle_info({gun_ws, _ConnPid, _StreamRef, {close, _, _}} = Data, State) -> %#state{socket = ConnPid} = State) ->
	?dbg("WS close: ~p", [Data]),
	{stop, normal, State};
handle_info({gun_ws, ConnPid, _StreamRef, {text, Data}}, #state{socket = ConnPid} = State) ->
	Map = jiffy:decode(Data, [return_maps]),
	?dbg("WS: RECEIVED: ~p", [Map]),
	handle_data(Map, State);
handle_info({gun_down, ConnPid, http, _, _} = GunDown, #state{socket = ConnPid} = State) -> %% only for ConnPid process
	?dbg("HTTP: GUN DOWN: ~p ", [GunDown]),
	handle_info(reconnect, State);
handle_info({gun_down, ConnPid, http, _, _} = GunDown, #state{} = State) -> %% should not be received otherwise look for unclosed pids
	?dbg("HTTP: WARNING: GUN DOWN: ~p ", [GunDown]),
	gun:close(ConnPid),
	{noreply, State};
handle_info({gun_down, _Pid, ws, _, _} = GunDown, State) -> %% TODO most likely will never be called because used protocol is "http"
	?dbg("WS: GUN DOWN: ~p", [GunDown]),
    {noreply, State};
handle_info({gun_up, ConnPid, http}, #state{socket = ConnPid} = State) ->  %% only for ConnPid process
	?dbg("HTTP: GUN UP", []),
	{noreply, State};
handle_info({gun_up, _, http}, State) ->
	{noreply, State};
handle_info({gun_data, ConnPid, _, nofin, Data}, #state{socket = ConnPid} = State) ->
	?dbg("WS: UNDER MAINTANANCE: ~p", [Data]),
	{noreply, State};
%%handle_info({'DOWN', MRef, process, Pid, Reason}, State) -> %% process not monitored by fun erlang:monitor/2 and cannot receive this message
%%	?dbg("WS DOWN:  Reason = ~p, STATE = ~p", [Reason, State]),
%%	close(Pid, MRef),
%%  {noreply, State};
handle_info(Data, State) ->
	?dbg("WS: UNEXPECTED: DATA = ~p, STATE = ~p", [Data, State]),
	{noreply, State}.

-spec terminate(term(), state()) -> term().
terminate(Reason, #state{socket = ConnPid, heartbeat_ref = HBRef, reconnect_ref = TRef}) ->
	?dbg("WS: TERMINATE REASON: ~p", [Reason]),
	[timer:cancel(Ref) || Ref <- [HBRef, TRef]],
	gun:close(ConnPid),
	ok.

-spec code_change(term(), state(), term()) -> {ok, state()}.
code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

%%%===================================================================
%%% Helpers
%%%===================================================================

handle_data(#{<<"method">> := <<"heartbeat">>, <<"params">> := #{<<"type">> := <<"test_request">>}},
			State = #state{socket = ConnPid, stream_ref = StreamRef}) ->
	gun:ws_send(ConnPid, StreamRef, {text, jiffy:encode(msg(<<"public/test">>, #{}))}),
	{noreply, State#state{heartbeat = erlang:system_time(millisecond)}};

handle_data(#{<<"result">> := #{<<"version">> := _},<<"testnet">> := true}, #state{} = State) ->
	?dbg("WS: TESTNET HEARTBEAT", []),
	{noreply, State#state{heartbeat = erlang:system_time(millisecond)}};
handle_data(#{<<"method">> := <<"heartbeat">>,<<"params">> := #{<<"type">> := <<"heartbeat">>}}, #state{} = State) ->
	?dbg("WS: HEARTBEAT", []),
	{noreply, State#state{heartbeat = erlang:system_time(millisecond)}};
handle_data(#{} = Map, State = #state{label_map = Labels, ids = Ids}) ->
	I = case Map of
		    #{<<"id">> := Id} -> Id;
		    #{<<"params">> := #{<<"label">> := Label}} -> erlang:phash2(Label);
		    _ -> 0
	    end,
	case Labels of
		#{I := Fun} -> spawn(fun() -> Fun(Map) end);
		_ -> ?dbg("WS: NOT FOUND: ~p", [Map])
	end,
	{noreply, State#state{ids = maps:remove(I, Ids)}};
handle_data(Data, State = #state{}) ->
	?dbg("WS: UNHANDLE: ~p", [Data]),
	{noreply, State}.

send_timeout(#state{ids = Ids} = State) ->
	maps:fold(
		fun(Id, Time, AccState) ->
			case is_timeout(Time, ?MODULE:timeout_interval()) of
				true -> {noreply, S} = handle_data(#{<<"id">> => Id, <<"error">> => <<"timeout">>}, State), S;
				_ -> AccState
			end
		end, State, Ids).
reconnect() ->
	{_, Pid, _, _} = lists:keyfind(eims_ws_client, 1, supervisor:which_children(eims)),
	Pid ! reconnect.

-spec get_port(list(), inet:port_number()) -> inet:port_number().
get_port(Args, Default) ->
	get_option(port, Args, Default).

-spec get_host(list(), string()) -> string().
get_host(Args, Default) ->
	maybe_binary_to_list(get_option(host, Args, Default)).

-spec get_resource(list(), string()) -> string().
get_resource(Args, Default) ->
	maybe_binary_to_list(get_option(wspath, Args, Default)).

-spec maybe_binary_to_list(binary() | string()) -> string().
maybe_binary_to_list(B) when is_binary(B) -> binary_to_list(B);
maybe_binary_to_list(S) when is_list(S) -> S.

-spec get_option(any(), list(), any()) -> any().
get_option(Key, Opts, Default) ->
	case lists:keyfind(Key, 1, Opts) of
		false -> Default;
		{Key, Value} -> Value
	end.

call(Data) ->
	gen_server:call(?MODULE, Data).

add_label(Label, Data) ->
	call({add_label, {Label, Data}}).
get_label(Label) ->
	call({get_label, Label}).
remove_label(Label) ->
	call({remove_label, Label}).
purge_labels() ->
	call(purge_labels).
labels() ->
	call(labels).

%% EIMS API

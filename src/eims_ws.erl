-module(eims_ws).

-behaviour(gen_server).

%% API
-export([socket_handoff/3]).
-export([start/1, start_link/1]).
-export([peername/1, setopts/2, send/2, close/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
	code_change/3, format_status/2]).

-define(SERVER, ?MODULE).

-include_lib("xmpp/include/xmpp.hrl").
-include("ejabberd_http.hrl").
-include("logger.hrl").

-define(SEND_TIMEOUT, timer:seconds(15)).

-record(state, {socket :: socket(),
	ws_pid :: pid(),
	client_pid :: undefined | pid()}).

-type peername() :: {inet:ip_address(), inet:port_number()}.
-type socket() :: {http_ws, pid(), peername()}.
-export_type([socket/0]).

%%%===================================================================
%%% API
%%%===================================================================
socket_handoff(LocalPath, Request, Opts) ->
	ejabberd_websocket:socket_handoff(
		LocalPath, Request, Opts, ?MODULE, fun get_human_html_xmlel/0).
-spec(start_link(WS :: #ws{}) ->
	{ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start({#ws{http_opts = Opts}, _} = WS) ->
	gen_server:start(?MODULE, [WS], ejabberd_config:fsm_limit_opts(Opts)).

start_link({#ws{http_opts = Opts}, _} = WS) ->
	gen_server:start_link(?MODULE, [WS], ejabberd_config:fsm_limit_opts(Opts)).

-spec peername(socket()) -> {ok, peername()}.
peername({http_ws, _, IP}) ->
	{ok, IP}.

-spec setopts(socket(), list()) -> ok.
setopts(_WSock, _Opts) ->
	ok.

-spec send(socket(), iodata()) -> ok | {error, timeout | einval}.
send({http_ws, Pid, _}, Data) ->
	try gen_server:call(Pid, {send, Data}, ?SEND_TIMEOUT)
	catch exit:{timeout, {gen_server, _, _}} ->
		{error, timeout};
		exit:{_, {gen_server, _, _}} ->
			{error, einval}
	end.

-spec close(socket()) -> ok.
close({http_ws, Pid, _}) ->
	gen_server:cast(Pid, close).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @private
%% @doc Initializes the server
-spec(init(Args :: term()) ->
	{ok, State :: #state{}} | {ok, State :: #state{}, timeout() | hibernate} |
	{stop, Reason :: term()} | ignore).
init([{#ws{ip = IP, http_opts = ListenOpts}, WsPid}]) ->
	Socket = {http_ws, self(), IP},
	case eims_session:start(?MODULE, Socket, ListenOpts) of
		{ok, Pid} ->
			erlang:monitor(process, Pid),
			erlang:monitor(process, WsPid),
			eims_session:accept(Pid),
			State = #state{socket = Socket,
				ws_pid = WsPid,
				client_pid = Pid},
			{ok, State};
		{error, Reason} ->
			{stop, Reason};
		ignore ->
			ignore
	end.

%% @private
%% @doc Handling call messages
-spec(handle_call(Request :: term(), From :: {pid(), Tag :: term()},
	State :: #state{}) ->
	{reply, Reply :: term(), NewState :: #state{}} |
	{reply, Reply :: term(), NewState :: #state{}, timeout() | hibernate} |
	{noreply, NewState :: #state{}} |
	{noreply, NewState :: #state{}, timeout() | hibernate} |
	{stop, Reason :: term(), Reply :: term(), NewState :: #state{}} |
	{stop, Reason :: term(), NewState :: #state{}}).
handle_call({send, Data}, _From, #state{ws_pid = WsPid} = State) ->
	WsPid ! {data, Data},
	{reply, ok, State};
handle_call(Request, From, State) ->
	?WARNING_MSG("Unexpected call from ~p: ~p", [From, Request]),
	{noreply, State}.

%% @private
%% @doc Handling cast messages
-spec(handle_cast(Request :: term(), State :: #state{}) ->
	{noreply, NewState :: #state{}} |
	{noreply, NewState :: #state{}, timeout() | hibernate} |
	{stop, Reason :: term(), NewState :: #state{}}).
handle_cast(_Request, State = #state{}) ->
	{noreply, State}.

%% @private
%% @doc Handling all non call/cast messages
-spec(handle_info(Info :: timeout() | term(), State :: #state{}) ->
	{noreply, NewState :: #state{}} |
	{noreply, NewState :: #state{}, timeout() | hibernate} |
	{stop, Reason :: term(), NewState :: #state{}}).
handle_info(closed, State) ->
	{stop, normal, State};
handle_info({received, Data}, State) ->
	State#state.client_pid ! {tcp, State#state.socket, Data},
	{noreply, State};
handle_info({'DOWN', _, process, Pid, _}, State)
	when Pid == State#state.client_pid orelse Pid == State#state.ws_pid ->
	{stop, normal, State};
handle_info(Info, State) ->
	?WARNING_MSG("Unexpected info: ~p", [Info]),
	{noreply, State}.

%% @private
%% @doc This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
-spec(terminate(Reason :: (normal | shutdown | {shutdown, term()} | term()),
	State :: #state{}) -> term()).
terminate(_Reason, State) ->
	if State#state.client_pid /= undefined ->
		State#state.client_pid ! {tcp_closed, State#state.socket};
		true ->
			ok
	end.

%% @private
%% @doc Convert process state when code is changed
-spec(code_change(OldVsn :: term() | {down, term()}, State :: #state{},
	Extra :: term()) ->
	{ok, NewState :: #state{}} | {error, Reason :: term()}).
code_change(_OldVsn, State = #state{}, _Extra) ->
	{ok, State}.

format_status(_Opt, Status) ->
	Status.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec get_human_html_xmlel() -> xmlel().
get_human_html_xmlel() ->
	Heading = <<"ejabberd mod_mqtt">>,
	#xmlel{name = <<"html">>,
		attrs =
		[{<<"xmlns">>, <<"http://www.w3.org/1999/xhtml">>}],
		children =
		[#xmlel{name = <<"head">>, attrs = [],
			children =
			[#xmlel{name = <<"title">>, attrs = [],
				children = [{xmlcdata, Heading}]}]},
			#xmlel{name = <<"body">>, attrs = [],
				children =
				[#xmlel{name = <<"h1">>, attrs = [],
					children = [{xmlcdata, Heading}]},
					#xmlel{name = <<"p">>, attrs = [],
						children =
						[{xmlcdata, <<"An implementation of ">>},
							#xmlel{name = <<"a">>,
								attrs =
								[{<<"href">>,
									<<"http://tools.ietf.org/html/rfc6455">>}],
								children =
								[{xmlcdata,
									<<"WebSocket protocol">>}]}]},
					#xmlel{name = <<"p">>, attrs = [],
						children =
						[{xmlcdata,
							<<"This web page is only informative. To "
							"use WebSocket connection you need an EIMS JSON "
							"client that supports it.">>}]}]}]}.

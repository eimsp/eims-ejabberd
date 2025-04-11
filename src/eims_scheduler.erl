-module(eims_scheduler).

-behaviour(gen_server).

-include("logger.hrl").

%% API
-export([start_link/0, drop_all/0]).

%% gen_server callbacks
-export([init/1, cast/1, stop/0, call/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
	code_change/3]).

-define(SERVER, ?MODULE).
-define(dbg(Fmt, Args),
	case xmpp_config:debug(global) of
		{ok, true} -> error_logger:info_msg(Fmt, Args);
		_ -> false
	end).

-record(private_data, {time_ref = [], counter = 0, data = []}).
-record(scheduler_state, {ref_map = #{}}).

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Spawns the server and registers the local name (unique)
-spec(start_link() ->
	{ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link() ->
	gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

call(Request) ->
	gen_server:call(?MODULE, Request).
cast(Request) ->
	gen_server:cast(?MODULE, Request).

-spec stop() -> ok | already_stopped.
stop() ->
	try
		gen_server:call(?MODULE, stop)
	catch
		exit:{noproc, {gen_server, call, _}} ->
			already_stopped;
		exit:{normal, {gen_server, call, _}} ->
			already_stopped
	end.

drop_all() ->
	?MODULE ! drop_all.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @private
%% @doc Initializes the server
-spec(init(Args :: term()) ->
	{ok, State :: #scheduler_state{}} | {ok, State :: #scheduler_state{}, timeout() | hibernate} |
	{stop, Reason :: term()} | ignore).
init([]) ->
	?dbg("Start scheduler", []),
	{ok, #scheduler_state{}}.

%% @private
%% @doc Handling call messages
-spec(handle_call(Request :: term(), From :: {pid(), Tag :: term()},
	State :: #scheduler_state{}) ->
	{reply, Reply :: term(), NewState :: #scheduler_state{}} |
	{reply, Reply :: term(), NewState :: #scheduler_state{}, timeout() | hibernate} |
	{noreply, NewState :: #scheduler_state{}} |
	{noreply, NewState :: #scheduler_state{}, timeout() | hibernate} |
	{stop, Reason :: term(), Reply :: term(), NewState :: #scheduler_state{}} |
	{stop, Reason :: term(), NewState :: #scheduler_state{}}).
handle_call({set_data, {_, _} = J, PrivData, TRef}, _From, State = #scheduler_state{ref_map = RefMap}) ->
	Counter =
		case RefMap of
			#{J := #private_data{time_ref = OldTRef, counter = I}} when is_reference(OldTRef)->
				erlang:cancel_timer(OldTRef), I;
			_ -> 0
		end,
	RefMapNew =
		case TRef of
			TRef when is_reference(TRef) ->
				RefMap#{J => #private_data{time_ref = TRef, counter = Counter + 1, data = PrivData}};
			[] -> maps:remove(J, RefMap);
			_ -> RefMap#{J => #private_data{data = PrivData}}
		end,
	{reply, {TRef, PrivData}, State#scheduler_state{ref_map = RefMapNew}};
handle_call({get_data, {_, _} = J}, _From, State = #scheduler_state{ref_map = RefMap}) ->
	PrivData = case RefMap of #{J := #private_data{data = Data}} -> Data; _ -> [] end,
	{reply, PrivData, State};
handle_call(get_state, _From, State) ->
	{reply, State, State};
handle_call(stop, _, S) ->
	{stop, normal, ok, S};
handle_call(_Request, _From, State = #scheduler_state{}) ->
	{reply, ok, State}.

%% @private
%% @doc Handling cast messages
-spec(handle_cast(Request :: term(), State :: #scheduler_state{}) ->
	{noreply, NewState :: #scheduler_state{}} |
	{noreply, NewState :: #scheduler_state{}, timeout() | hibernate} |
	{stop, Reason :: term(), NewState :: #scheduler_state{}}).
handle_cast({apply, Fun}, State = #scheduler_state{}) when is_function(Fun) ->
	Fun(),
	{noreply, State};
handle_cast(_Request, State = #scheduler_state{}) ->
	{noreply, State}.

%% @private
%% @doc Handling all non call/cast messages
-spec(handle_info(Info :: timeout() | term(), State :: #scheduler_state{}) ->
	{noreply, NewState :: #scheduler_state{}} |
	{noreply, NewState :: #scheduler_state{}, timeout() | hibernate} |
	{stop, Reason :: term(), NewState :: #scheduler_state{}}).
handle_info(drop_all, State = #scheduler_state{ref_map = RefMap}) ->
	?dbg("SCHEDULER: DROP ALL", []),
	maps:foreach(
		fun(_Key, #private_data{time_ref = TRef}) ->
			erlang:cancel_timer(TRef)
		end, RefMap),
	{noreply, State#scheduler_state{ref_map = #{}}};
handle_info({eims_send, Jid, Fun}, State = #scheduler_state{ref_map = RefMap}) ->
	PrivData2 = case RefMap of #{Jid := #private_data{data = PrivData}} -> PrivData; _ -> [] end,
	spawn(fun() -> Fun(PrivData2) end),
	{noreply, State};
handle_info(_Info, State = #scheduler_state{}) ->
	{noreply, State}.

%% @private
%% @doc This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
-spec(terminate(Reason :: (normal | shutdown | {shutdown, term()} | term()),
	State :: #scheduler_state{}) -> term()).
terminate(_Reason, _State = #scheduler_state{}) ->
	ok.

%% @private
%% @doc Convert process state when code is changed
-spec(code_change(OldVsn :: term() | {down, term()}, State :: #scheduler_state{},
	Extra :: term()) ->
	{ok, NewState :: #scheduler_state{}} | {error, Reason :: term()}).
code_change(_OldVsn, State = #scheduler_state{}, _Extra) ->
	{ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
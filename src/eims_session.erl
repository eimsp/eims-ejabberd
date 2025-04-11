-module(eims_session).

%% API
-behaviour(p1_server).
-define(VSN, 2).
-vsn(?VSN).

%% API
-export([start/3, start_link/3, accept/1, route/2, send_timeout/2, rate_limit/0, is_valid_heartbeat/1]).
%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	terminate/2, code_change/3]).

-import(eims_api_codec, [packet_error/1, packet_result/1]).

-include("logger.hrl").
-include("eims.hrl").
-include_lib("xmpp/include/xmpp.hrl").
-include_lib("public_key/include/public_key.hrl").
-include_lib("eims_api_codec.hrl").

-record(state, {vsn = ?VSN            :: integer(),
	version               :: undefined,
	socket                :: undefined | socket(),
	peername              :: undefined | peername(),
	timeout = infinity    :: timer(),
	jid                   :: undefined | jid:jid(),
	nick                  :: undefined | binary(),
	session_expiry = 0    :: milli_seconds(),
	will_delay = 0        :: milli_seconds(),
	stop_reason           :: undefined | error_reason(),
	id = 0                :: non_neg_integer(),
	queue                 :: undefined,
	ids              = [] :: list(), %% TODO implement timeout
	count            = 0  :: integer(),
	counting_time    = 0  :: integer(),
	limit_tref            :: undefined | timer:tref(),
	heartbeat_interval = 0 :: integer(),
	heartbeat_tref        :: undefined | timer:tref(),
	heartbeat_time    = 0 :: integer(),
	tls                   :: boolean(),
	tls_verify            :: boolean()}).

-type reason_code() :: 'success' |
						'normal-disconnection' |
						're-authenticate' |
						'unspecified-error' |
						'malformed-packet' |
						'protocol-error' |
						'not-authorized' |
						'server-unavailable' |
						'server-busy' |
						'banned' |
						'server-shutting-down' |
						'bad-authentication-method' |
						'keep-alive-timeout' |
						'session-taken-over'.

-type error_reason() :: {auth, reason_code()} |
						{code, reason_code()} |
						{peer_disconnected, reason_code(), binary()} |
		{socket, socket_error_reason()} |
		{unexpected_packet, atom()} |
		{tls, inet:posix() | atom() | binary()} |
		{replaced, pid()} | {resumed, pid()} |
		internal_server_error |
		session_expired | idle_connection |
		queue_full | shutdown | db_failure |
		session_expiry_non_zero.

-type state() :: #state{}.
-type socket() :: {gen_tcp, inet:socket()} |
		{fast_tls, fast_tls:tls_socket()} |
		{eims_ws, eims_ws_client:socket()}.
-type peername() :: {inet:ip_address(), inet:port_number()}.
-type seconds() :: non_neg_integer().
-type milli_seconds() :: non_neg_integer().
-type timer() :: infinity | {milli_seconds(), integer()}.
-type socket_error_reason() :: closed | timeout | inet:posix().

-define(CALL_TIMEOUT, timer:seconds(5)).
-define(RELAY_TIMEOUT, timer:minutes(1)).
-define(MAX_UINT32, 4294967295).
-define(RATE_LIMIT, 20). %% per second
-define(MIN_HEARTBEAT_INTRVAL, 10).
-define(MAX_HEARTBEAT_INTRVAL, 30).

rate_limit() -> ?RATE_LIMIT.
%%%===================================================================
%%% API
%%%===================================================================
start(SockMod, Socket, ListenOpts) ->
	p1_server:start(?MODULE, [SockMod, Socket, ListenOpts],
		ejabberd_config:fsm_limit_opts(ListenOpts)).

start_link(SockMod, Socket, ListenOpts) ->
	p1_server:start_link(?MODULE, [SockMod, Socket, ListenOpts],
		ejabberd_config:fsm_limit_opts(ListenOpts)).

-spec accept(pid()) -> ok.
accept(Pid) ->
	p1_server:cast(Pid, accept).

-spec route(pid(), term()) -> boolean().
route(Pid, Term) ->
	ejabberd_cluster:send(Pid, Term).

-spec format_error(error_reason()) -> string().
format_error(session_expired) ->
	"Disconnected session is expired";
format_error(idle_connection) ->
	"Idle connection";
format_error(queue_full) ->
	"Message queue is overloaded";
format_error(internal_server_error) ->
	"Internal server error";
format_error(db_failure) ->
	"Database failure";
format_error(shutdown) ->
	"System shutting down";
format_error(subscribe_forbidden) ->
	"Subscribing to this topic is forbidden by service policy";
format_error(publish_forbidden) ->
	"Publishing to this topic is forbidden by service policy";
format_error(will_topic_forbidden) ->
	"Publishing to this will topic is forbidden by service policy";
format_error(session_expiry_non_zero) ->
	"Session Expiry Interval in DISCONNECT packet should have been zero";
format_error(unknown_topic_alias) ->
	"No mapping found for this Topic Alias";
format_error({payload_format_invalid, will}) ->
	"Will payload format doesn't match its indicator";
format_error({payload_format_invalid, publish}) ->
	"PUBLISH payload format doesn't match its indicator";
format_error({peer_disconnected, Code, <<>>}) ->
	format("Peer disconnected with reason: ~ts",
		[mqtt_codec:format_reason_code(Code)]);
format_error({peer_disconnected, Code, Reason}) ->
	format("Peer disconnected with reason: ~ts (~ts)", [Reason, Code]);
format_error({replaced, Pid}) ->
	format("Replaced by ~p at ~ts", [Pid, node(Pid)]);
format_error({resumed, Pid}) ->
	format("Resumed by ~p at ~ts", [Pid, node(Pid)]);
format_error({unexpected_packet, Name}) ->
	format("Unexpected ~ts packet", [string:to_upper(atom_to_list(Name))]);
format_error({tls, Reason}) ->
	format("TLS failed: ~ts", [format_tls_error(Reason)]);
format_error({socket, A}) ->
	format("Connection failed: ~ts", [format_inet_error(A)]);
format_error({code, Code}) ->
	format("Protocol error: ~ts", [mqtt_codec:format_reason_code(Code)]);
format_error({auth, Code}) ->
	format("Authentication failed: ~ts", [mqtt_codec:format_reason_code(Code)]);
format_error({codec, CodecError}) ->
	format("Protocol error: ~ts", [mqtt_codec:format_error(CodecError)]);
format_error(A) when is_atom(A) ->
	atom_to_list(A);
format_error(Reason) ->
	format("Unrecognized error: ~w", [Reason]).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% @private
%% @doc Initializes the server
-spec(init(Args :: list()) ->
	{ok, State :: #state{}} | {ok, State :: #state{}, timeout() | hibernate} |
	{stop, Reason :: term()} | ignore).
init([SockMod, Socket, ListenOpts]) ->
%%	MaxSize = proplists:get_value(max_payload_size, ListenOpts, infinity),
	State1 = #state{socket = {SockMod, Socket},
		version = <<"1.0">>,
		id = p1_rand:uniform(65535),
		queue = p1_queue:new(),
		tls = proplists:get_bool(tls, ListenOpts),
		tls_verify = proplists:get_bool(tls_verify, ListenOpts)},
	Timeout = timer:seconds(30),
	State2 = set_timeout(State1, Timeout),
	{ok, State2, Timeout}.


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
handle_call({get_state, _}, From, #state{stop_reason = {resumed, Pid}} = State) ->
	p1_server:reply(From, {error, {resumed, Pid}}),
	noreply(State);
handle_call({get_state, Pid}, From, State) ->
	case stop(State, {resumed, Pid}) of
		{stop, Status, State1} ->
			{stop, Status, State1#state{stop_reason = {replaced, Pid}}};
		{noreply, State1, _} ->
			?dbg("Transferring eims session state to ~p at ~ts", [Pid, node(Pid)]),
			Q1 = p1_queue:file_to_ram(State1#state.queue),
			p1_server:reply(From, {ok, State1#state{queue = Q1}}),
			SessionExpiry = State1#state.session_expiry,
			State2 = set_timeout(State1, min(SessionExpiry, ?RELAY_TIMEOUT)),
			State3 = State2#state{queue = undefined,
				stop_reason = {resumed, Pid},
				session_expiry = 0},
			noreply(State3)
	end;
handle_call(Request, From, State) ->
	?WARNING_MSG("Unexpected call from ~p: ~p", [From, Request]),
	noreply(State).

%% @private
%% @doc Handling cast messages
-spec(handle_cast(Request :: term(), State :: #state{}) ->
	{noreply, NewState :: #state{}} |
	{noreply, NewState :: #state{}, timeout() | hibernate} |
	{stop, Reason :: term(), NewState :: #state{}}).
handle_cast(accept, #state{socket = {_, Sock}} = State) ->
	case peername(State) of
		{ok, IPPort} ->
			State1 = State#state{peername = IPPort},
			case starttls(State) of
				{ok, Socket1} ->
					State2 = State1#state{socket = Socket1},
					handle_info({tcp, Sock, <<>>}, State2);
				{error, Why} ->
					stop(State1, Why)
			end;
		{error, Why} ->
			stop(State, {socket, Why})
	end;
handle_cast(Msg, State) ->
	?WARNING_MSG("Unexpected cast: ~p", [Msg]),
	noreply(State).

%% @private
%% @doc Handling all non call/cast messages
-spec(handle_info(Info :: timeout() | term(), State :: #state{}) ->
	{noreply, NewState :: #state{}} |
	{noreply, NewState :: #state{}, timeout() | hibernate} |
	{stop, Reason :: term(), NewState :: #state{}}).
handle_info(Msg, #state{stop_reason = {resumed, Pid} = Reason} = State) ->
	ejabberd_cluster:send(Pid, Msg),
	noreply(State);
handle_info({tcp, TCPSock, <<"ping">>}, State) ->
	noreply(do_send(State, <<"pong">>));
handle_info({tcp, TCPSock, TCPData}, #state{socket = Socket} = State) ->
	case recv_data(Socket, TCPData) of
		{ok, Data} ->
			case eims_api_codec:decode(Data) of
				{ok, Pkt} ->
					?dbg("Got JSON packet:~n~p", [Pkt]),
					{ok, State2} = handle_packet(Pkt, State),
					noreply(State2);
				more ->
					State2 = reset_keep_alive(State),
					activate(Socket),
					noreply(State2);
				#packet_error{} = ErrPkt ->
					noreply(do_send(State, ErrPkt))
			end;
		{error, Why} ->
			stop(State, Why)
	end;
handle_info({send, #packet{method = ?HEARTBEAT} = Pkt}, #state{heartbeat_tref = HBRef} = State) ->
	timer:cancel(HBRef),
	{ok, NewHBRef} = timer:send_after(500, self(), {tcp_closed, close_heartbeat}),
	noreply(do_send(State#state{heartbeat_tref = NewHBRef, heartbeat_time = erlang:system_time(microsecond)}, Pkt));
handle_info({send, Pkt}, #state{} = State) ->
	noreply(do_send(State, Pkt));
handle_info({tcp_closed, _Sock}, State) ->
	?dbg("WS connection reset by peer", []),
	stop(State, {socket, closed});
handle_info({tcp_error, _Sock, Reason}, State) ->
	?dbg("WS connection error: ~ts", [format_inet_error(Reason)]),
	stop(State, {socket, Reason});
handle_info(timeout, #state{socket = Socket} = State) ->
	case Socket of
		undefined ->
			?dbg("WS session expired", []),
			stop(State#state{session_expiry = 0}, session_expired);
		_ ->
			?dbg("WS connection timed out", []),
			stop(State, idle_connection)
	end;
handle_info({replaced, Pid}, State) ->
	stop(State#state{session_expiry = 0}, {replaced, Pid});
handle_info({timeout, _TRef, publish_will}, State) ->
	noreply(State); %% TODO send timeout
%%	noreply(publish_will(State));
handle_info({Ref, badarg}, State) when is_reference(Ref) ->
	%% TODO: figure out from where this messages comes from
	noreply(State);
handle_info(Info, State) ->
	?dbg("Unexpected info: ~p", [Info]),
	noreply(State).

-spec handle_packet(packet() , state()) -> {ok, state()} | {error, state(), error_reason()}.
handle_packet(#packet{method = ?SUBSCRIPTION} = Pkt, State) ->
	send(State, (packet_error(Pkt))#packet_error{code = -32601, message = <<"Method not found">>,
		data = #{<<"reason">> => <<"Method '", ?SUBSCRIPTION/binary, "' not found">>}});
handle_packet(#packet{method = ?DERIBIT_TEST} = Pkt,
	#state{heartbeat_tref = HBRef, heartbeat_interval = Interval} = State) ->
	timer:cancel(HBRef),
	State2 = #state{version = V, heartbeat_time = HBTime} =
		case Interval > 0 of
			true ->
				{ok, NewHBRef} = timer:send_after(1000 * Interval, self(),
					{send, #packet{method = ?HEARTBEAT, params = #{<<"type">> => <<"type_request">>}}}),
				State#state{heartbeat_tref = NewHBRef};
			_ -> State
		end,
	case {HBTime, Interval > 0} of
		{0, true} -> {ok, State2};
		_ -> send(State2, (packet_result(Pkt))#packet_result{result = #{<<"version">> => V}})
	end;
handle_packet(#packet{method = ?SET_HEARTBEAT, params = #{<<"interval">> := Interval}} = Pkt, #state{} = State) ->
	case ?MODULE:is_valid_heartbeat(Interval) of %% TODO move to eims_api_codec module
		true ->
			{ok, State2} = handle_packet(Pkt#packet{method = ?DERIBIT_TEST}, State#state{heartbeat_interval = Interval}),
			send(State2, (packet_result(Pkt))#packet_result{result = <<"ok">>});
		_ ->
			send(State, (packet_error(Pkt))#packet_error{code = 11029, message = "invalid_arguments"}) %% TODO update error code and message and move to eims_api_codec
	end;
handle_packet(#packet{method = ?DISABLE_HEARTBEAT} = Pkt, #state{heartbeat_tref = HBRef} = State) ->
	timer:cancel(HBRef),
	send(State#state{heartbeat_tref = undefined, heartbeat_interval = 0, heartbeat_time = 0},
			(packet_result(Pkt))#packet_result{result = <<"ok">>});
handle_packet(#packet{id = Id, time_ref = undefined} = Pkt, #state{count = Count, counting_time = CT} = State) ->
	SysTime = erlang:system_time(millisecond),
	NewCT = (SysTime div 1000) * 1000,
	NewCount = case NewCT > CT of true -> 1; _ -> Count + 1 end,
	case NewCount == 1 orelse NewCount =< ?MODULE:rate_limit() of
		true ->
			{ok, TRef} = timer:apply_after(?CALL_TIMEOUT, ?MODULE, send_timeout, [self(), Id]),
			handle_packet(Pkt#packet{time_ref = TRef}, State#state{counting_time = NewCT, count = NewCount, limit_tref = TRef});
		_ ->
			send(State#state{counting_time = NewCT, count = Count + 1}, (packet_error(Pkt))#packet_error{code = 10047, message = <<"matching_engine_queue_full">>})
	end;
handle_packet(#packet{method = <<"private/", _/binary>>} = Pkt, #state{jid = undefined} = State) ->
	send(State, (packet_error(Pkt))#packet_error{code = 13009, message = <<"unauthorized">>});
handle_packet(#packet{method = ?AUTH, id = Id, params = #{<<"access_token">> := Token, <<"refresh_token">> := RefreshToken}} = Pkt, State) ->
	case eims_rest:get_account_summary_req(Token) of
		{ok, 200, #{<<"jid_node">> := User, <<"nick">> := Nick} = Summary} ->
			JID = jid:make(User, ?HOST),
			case State of
				#state{jid = UserJID} when UserJID == JID; UserJID == undefined ->
					case eims:get_tokens(JID) of
						[] ->
							send(State, (packet_error(Pkt))#packet_error{code = 13009, message = <<"Unauthorized">>});
						#eims_auth{} = AuthData ->
							{_, _} = eims:set_tokens(JID, AuthData#eims_auth{access_token = Token, refresh_token = RefreshToken}, undefined), %% TODO refresh token?
							mod_eims:add_client_pid(JID),
							send(State#state{jid = JID, nick = Nick}, (packet_result(Pkt))#packet_result{result = Summary})
					end;
				_ ->
					stop(State, {auth, 're-authenticate'}) %% TODO send reason if other user wants to authorize
			end;
		{error, _, #{<<"error">> := _}} = Err ->
			?err("WS HANDLE_PACKET: ~p", [Err]),
			send(State, Err#{<<"id">> => Id}); %% TODO generate own error?
		{error, bad_request} ->
			send(State, (packet_error(Pkt))#packet_error{code = 11050, message = <<"bad_request">>})
	end;
handle_packet(#packet{method = ?GET_MARKET_PLACES} = Pkt, State) ->
	RfqChannels = [Name || {<<"rfq.", _/binary>> = Name, _, _} <- mod_muc:get_online_rooms(?MUC_HOST)],
	send(State, (packet_result(Pkt))#packet_result{result = #{channels => RfqChannels}});
handle_packet(#packet{method = ?COUNTERPARTIES, params = #{<<"channel">> := <<"rfq.", _/binary>> = Room}} = Pkt, State) ->
	ResPkt = case catch mod_muc_admin:get_room_occupants(Room, ?MUC_HOST) of %% TODO get room occupants or online room subscribers?
		         {error, room_not_found} ->
			         (packet_error(Pkt))#packet_error{code = 13020, message = <<"not_found">>};
		         Occupants ->
			         (packet_result(Pkt))#packet_result{result = #{<<"channel">> => Room, <<"data">> => #{<<"Parties">> => [Nick || {_, Nick, _} <- Occupants]}}}
	         end, send(State, ResPkt);
handle_packet(#packet{method = ?COUNTERPARTIES, params = #{<<"channel">> := _}} = Pkt, State) ->
	send(State, (packet_error(Pkt))#packet_error{code = 14002, message = <<"invalid_channel">>}); %% TODO add code in future
handle_packet(#packet{method = ?RFQ_REQ, params = #{<<"channel">> := Channel}} = Pkt,
	#state{jid = #jid{user = User, server = Server} = JID, nick = Nick} = State) ->
	MucHost = ?MUC_HOST,
	ResponsePkt =
		case catch mod_muc_admin:get_room_occupants(Channel, MucHost) of %% TODO get room occupants or online room subscribers?
			 {error, room_not_found} ->
				 ?err("The channel '~s' not found: ~p: ~p", [Channel]),
				 (packet_error(Pkt))#packet_error{code = 14000, message = <<"channel_not_found">>, %% TODO come up with code number and message
					                              data = #{<<"channel">> => Channel, <<"reason">> => <<"the channel not found">>}};
			 Occupants ->
				 ResPkt = (packet_result(Pkt))#packet_result{result = #{<<"message">> => <<"ok">>, <<"channel">> => Channel}},
				 case lists:keyfind(Nick, 2, Occupants) of
					 {Jid, Nick, _} ->
						 case jid:remove_resource(jid:decode(Jid)) of
							 JID -> ResPkt;
							 J ->
								 ?err("another user with this nickname is in the channel '~s' : ~p: ~p", [Channel, J, JID]),
								 (packet_error(Pkt))#packet_error{code = 14001, message = <<"channel_not_available">>, %% TODO come up with code number and message
				                        data = #{<<"channel">> => Channel, <<"reason">> => <<"another user with same nickname is in the channel">>}}
						 end;
					 false ->
						 [Resource | _] = ejabberd_sm:get_user_resources(User, Server),
						 eims_rest:auth_post(#{jid => jid:encode(jid:replace_resource(JID, Resource)),
							                      pmuc => jid:to_string({Channel, MucHost, <<>>}),
							                      nick => Nick}),
						 ResPkt
				 end
		 end,
	case ResponsePkt of #packet_result{} -> mod_eims:add_client_pid(JID, self(), [Channel]); _ -> ok end,
	send(State, ResponsePkt);
handle_packet(#packet{method = <<"private/", Cmd/binary>>, params = #{<<"channel">> := <<"rfq.", _/binary>> = Room} = Params} = Pkt,
	#state{jid = BareJID} = State) ->
	BotNick = eims:bot_nick(),
	MucJID = jid:make(Room, ?MUC_HOST),
	case get_user_resource(BareJID) of
		{ok, _Resource} ->
			case find_occupant(State, Pkt) of
				#packet_error{} = ErrPkt ->
					send(State, ErrPkt); %% TODO error code
				{ok, JID} ->
					Text = case Params of
						       #{<<"data">> := #{} = Body} -> jiffy:encode(Body);
						       #{<<"data">> := Args} when is_list(Args) -> eims:binary_join(Args, <<" ">>)
					       end,
					mdrfq_umarket:route(JID, MucJID, BotNick, <<"/", Cmd/binary, " ", Text/binary>>, [],
									 eims:gen_uuid(), #{from => {self(), JID, Pkt}}),
					{ok, State}
			end;
		{error, offline} ->
			do_send(State, (packet_error(Pkt))#packet_error{code = 10000, message = <<"authorization_required">>,
															data = #{<<"reason">> => <<"XMPP user is offline">>}}), %% TODO error code
			stop(State, <<"XMPP user offline">>) %% TODO send error
	end;
handle_packet(#packet{} = Pkt, State) ->
	send(State, (packet_error(Pkt))#packet_error{code = 11029, message = <<"invalid_arguments">>}).

%% @private
%% @doc This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
-spec(terminate(Reason :: (normal | shutdown | {shutdown, term()} | term()),
	State :: #state{}) -> term()).
terminate(_Reason, #state{limit_tref = LimitTRef, heartbeat_tref = HBRef} = _State) ->
	mod_eims:remove_client_pid(),
	timer:cancel(LimitTRef),
	timer:cancel(HBRef),
	ok.

%% @private
%% @doc Convert process state when code is changed
-spec(code_change(OldVsn :: term() | {down, term()}, State :: #state{},
	Extra :: term()) ->
	{ok, NewState :: #state{}} | {error, Reason :: term()}).
code_change(_OldVsn, State = #state{}, _Extra) ->
	{ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%%%===================================================================
%%% State transitions
%%%===================================================================
-spec noreply(state()) -> {noreply, state(), non_neg_integer() | infinity}.
noreply(#state{timeout = infinity} = State) ->
	{noreply, State, infinity};
noreply(#state{timeout = {MSecs, StartTime}} = State) ->
	CurrentTime = current_time(),
	Timeout = max(0, MSecs - CurrentTime + StartTime),
	{noreply, State, Timeout}.

-spec stop(state(), error_reason()) -> {noreply, state(), infinity} |
{stop, normal, state()}.
stop(#state{session_expiry = 0} = State, Reason) ->
	?dbg("STOP WS", []),
	{stop, normal, State#state{stop_reason = Reason}};
stop(#state{session_expiry = SessExp} = State, Reason) ->
	case State#state.socket of
		undefined ->
			noreply(State);
		_ ->
%%			WillDelay = State#state.will_delay,
			log_disconnection(State, Reason),
			State1 = disconnect(State, Reason),
%%			State2 = if WillDelay == 0 ->
%%				publish_will(State1);
%%				         WillDelay < SessExp ->
%%					         erlang:start_timer(WillDelay, self(), publish_will),
%%					         State1;
%%				         true ->
%%					         State1
%%			         end,
			State3 = set_timeout(State1, SessExp),
			State4 = State3#state{stop_reason = Reason},
			noreply(State4)
	end.

%%%===================================================================
%%% Formatters
%%%===================================================================
%%-spec pp(any()) -> iolist().
%%pp(Term) ->
%%	io_lib_pretty:print(Term, fun pp/2).

-spec format_inet_error(socket_error_reason()) -> string().
format_inet_error(closed) ->
	"connection closed";
format_inet_error(timeout) ->
	format_inet_error(etimedout);
format_inet_error(Reason) ->
	case inet:format_error(Reason) of
		"unknown POSIX error" -> atom_to_list(Reason);
		Txt -> Txt
	end.

-spec format_tls_error(atom() | binary()) -> string() | binary().
format_tls_error(no_certfile) ->
	"certificate not configured";
format_tls_error(Reason) when is_atom(Reason) ->
	format_inet_error(Reason);
format_tls_error(Reason) ->
	Reason.

-spec format_exit_reason(term()) -> string().
format_exit_reason(noproc) ->
	"process is dead";
format_exit_reason(normal) ->
	"process has exited";
format_exit_reason(killed) ->
	"process has been killed";
format_exit_reason(timeout) ->
	"remote call to process timed out";
format_exit_reason(Why) ->
	format("unexpected error: ~p", [Why]).

%% Same as format_error/1, but hides sensitive data
%% and returns result as binary
-spec format_reason_string(error_reason()) -> binary().
format_reason_string({resumed, _}) ->
	<<"Resumed by another connection">>;
format_reason_string({replaced, _}) ->
	<<"Replaced by another connection">>;
format_reason_string(Err) ->
	list_to_binary(format_error(Err)).

-spec format(io:format(), list()) -> string().
format(Fmt, Args) ->
	lists:flatten(io_lib:format(Fmt, Args)).

%%-spec pp(atom(), non_neg_integer()) -> [atom()] | no.
%%pp(state, 17) -> record_info(fields, state);
%%pp(Rec, Size) -> mqtt_codec:pp(Rec, Size).

%%%===================================================================
%%% Timings
%%%===================================================================
-spec set_timeout(state(), milli_seconds()) -> state().
set_timeout(State, MSecs) ->
	Time = current_time(),
	State#state{timeout = {MSecs, Time}}.

-spec current_time() -> milli_seconds().
current_time() ->
	erlang:monotonic_time(millisecond).

-spec reset_keep_alive(state()) -> state().
reset_keep_alive(#state{timeout = {MSecs, _}, jid = #jid{}} = State) ->
	set_timeout(State, MSecs);
reset_keep_alive(State) ->
	State.

%%%===================================================================
%%% Misc
%%%===================================================================
-spec err_args(undefined | jid:jid(), peername(), error_reason()) -> iolist().
err_args(undefined, IP, Reason) ->
	[ejabberd_config:may_hide_data(misc:ip_to_list(IP)),
		format_error(Reason)];
err_args(JID, IP, Reason) ->
	[jid:encode(JID),
		ejabberd_config:may_hide_data(misc:ip_to_list(IP)),
		format_error(Reason)].

-spec log_disconnection(state(), error_reason()) -> ok.
log_disconnection(#state{jid = JID, peername = IP}, Reason) ->
	Msg = case JID of
		      undefined -> "Rejected WS connection from ~ts: ~ts";
		      _ -> "Closing WS connection for ~ts from ~ts: ~ts"
	      end,
	case Reason of
		{Tag, _} when Tag == replaced; Tag == resumed; Tag == socket ->
			?dbg(Msg, err_args(JID, IP, Reason));
		idle_connection ->
			?dbg(Msg, err_args(JID, IP, Reason));
		Tag when Tag == session_expired; Tag == shutdown ->
			?dbg(Msg, err_args(JID, IP, Reason));
%%		{peer_disconnected, Code, _} ->
%%			case mqtt_codec:is_error_code(Code) of
%%				true -> ?WARNING_MSG(Msg, err_args(JID, IP, Reason));
%%				false -> ?dbg(Msg, err_args(JID, IP, Reason))
%%			end;
		_ ->
			?dbg(Msg, err_args(JID, IP, Reason))
	end.

%%%===================================================================
%%% Socket management
%%%===================================================================
-spec send(state(), map()) -> {ok, state()} |
{error, state(), error_reason()}.
%%send(State, #{} = Pkt) ->
%%	case is_expired(Pkt) of
%%		{false, Pkt1} ->
%%			case State#state.in_flight == undefined andalso
%%				p1_queue:is_empty(State#state.queue) of
%%				true ->
%%					Dup = case Pkt1#publish.qos of
%%						      0 -> undefined;
%%						      _ -> Pkt1
%%					      end,
%%					State1 = State#state{in_flight = Dup},
%%					{ok, do_send(State1, Pkt1)};
%%				false ->
%%					?dbg("Queueing packet:~n~ts~n** when state:~n~ts",
%%						[pp(Pkt), pp(State)]),
%%					try p1_queue:in(Pkt, State#state.queue) of
%%						Q ->
%%							State1 = State#state{queue = Q},
%%							{ok, State1}
%%					catch error:full ->
%%						Q = p1_queue:clear(State#state.queue),
%%						State1 = State#state{queue = Q, session_expiry = 0},
%%						{error, State1, queue_full}
%%					end
%%			end;
%%		true ->
%%			{ok, State}
%%	end;
send(#state{} = State, Pkt) ->
	{ok, do_send(State, Pkt)}.

%%-spec resend(state()) -> {ok, state()} | {error, state(), error_reason()}.
%%resend(#state{in_flight = undefined} = State) ->
%%	case p1_queue:out(State#state.queue) of
%%		{{value, #publish{qos = QoS} = Pkt}, Q} ->
%%			case is_expired(Pkt) of
%%				true ->
%%					resend(State#state{queue = Q});
%%				{false, Pkt1} when QoS > 0 ->
%%					State1 = State#state{in_flight = Pkt1, queue = Q},
%%					{ok, do_send(State1, Pkt1)};
%%				{false, Pkt1} ->
%%					State1 = do_send(State#state{queue = Q}, Pkt1),
%%					resend(State1)
%%			end;
%%		{empty, _} ->
%%			{ok, State}
%%	end;
%%resend(#state{in_flight = Pkt} = State) ->
%%	{ok, do_send(State, set_dup_flag(Pkt))}.

-spec do_send(state(), map()) -> state().
do_send(#state{socket = {SockMod, Sock} = Socket} = State, <<"pong">> = Data) ->
	Res = SockMod:send(Sock, Data),
	check_sock_result(Socket, Res),
	State;
do_send(#state{socket = {SockMod, Sock} = Socket} = State, Pkt) ->
	?dbg("Send JSON packet:~n~p", [Pkt]),
	case eims_api_codec:encode_pkt(Pkt) of
		{ok, Data} ->
			timer:cancel(element(3, Pkt)),
			Res = SockMod:send(Sock, Data),
			check_sock_result(Socket, Res),
			State;
		{error, _} ->
			?err("invalid packet: ~p", [Pkt]),
			State
	end;
do_send(State, _Pkt) ->
	State.

-spec activate(socket()) -> ok.
activate({SockMod, Sock} = Socket) ->
	Res = case SockMod of
		      gen_tcp -> inet:setopts(Sock, [{active, once}]);
		      _ -> SockMod:setopts(Sock, [{active, once}])
	      end,
	check_sock_result(Socket, Res).

-spec peername(state()) -> {ok, peername()} | {error, socket_error_reason()}.
peername(#state{socket = {SockMod, Sock}}) ->
	case SockMod of
		gen_tcp -> inet:peername(Sock);
		_ -> SockMod:peername(Sock)
	end.

-spec disconnect(state(), error_reason()) -> state().
disconnect(#state{socket = {SockMod, Sock}} = State, Err) ->
	State1 = case Err of
		         {auth, Code} -> ok;
%%			         do_send();
%%			         do_send(State, #connack{code = Code});
%%		         {codec, {Tag, _, _}} when Tag == unsupported_protocol_version;
%%			         Tag == unsupported_protocol_name ->
%%			         do_send(State#state{version = ?MQTT_VERSION_4},
%%				         #connack{code = connack_reason_code(Err)});
		         _ when State#state.version == undefined ->
			         State;
		         {Tag, _} when Tag == socket; Tag == tls ->
			         State;
		         {peer_disconnected, _, _} ->
			         State;
		         _ ->
			         Props = #{reason_string => format_reason_string(Err)},
			         case State#state.jid of
				         undefined ->
%%					         do_send(),
					         State;
%%					         Code = connack_reason_code(Err),
%%					         Pkt = #connack{code = Code, properties = Props},
%%					         do_send(State, Pkt);
%%				         _ when State#state.version == ?MQTT_VERSION_5 ->
%%					         Code = disconnect_reason_code(Err),
%%					         Pkt = #disconnect{code = Code, properties = Props},
%%					         do_send(State, Pkt);
				         _ ->
					         State
			         end
	         end,
	SockMod:close(Sock),
	State1#state{socket = undefined,
		version = undefined};
disconnect(State, _) ->
	State.

-spec check_sock_result(socket(), ok | {error, inet:posix()}) -> ok.
check_sock_result(_, ok) ->
	ok;
check_sock_result({_, Sock}, {error, Why}) ->
	self() ! {tcp_closed, Sock},
	?dbg("WS socket error: ~p", [format_inet_error(Why)]).

-spec starttls(state()) -> {ok, socket()} | {error, error_reason()}.
starttls(#state{socket = {gen_tcp, Socket}, tls = true}) ->
	case ejabberd_pkix:get_certfile() of
		{ok, Cert} ->
			CAFileOpt =
				case ejabberd_option:c2s_cafile(ejabberd_config:get_myname()) of
					undefined -> [];
					CAFile -> [{cafile, CAFile}]
				end,
			case fast_tls:tcp_to_tls(Socket, [{certfile, Cert}] ++ CAFileOpt) of
				{ok, TLSSock} ->
					{ok, {fast_tls, TLSSock}};
				{error, Why} ->
					{error, {tls, Why}}
			end;
		error ->
			{error, {tls, no_certfile}}
	end;
starttls(#state{socket = Socket}) ->
	{ok, Socket}.

-spec recv_data(socket(), binary()) -> {ok, binary()} | {error, error_reason()}.
recv_data({fast_tls, Sock}, Data) ->
	case fast_tls:recv_data(Sock, Data) of
		{ok, _} = OK -> OK;
		{error, E} when is_atom(E) -> {error, {socket, E}};
		{error, E} when is_binary(E) -> {error, {tls, E}}
	end;
recv_data(_, Data) ->
	{ok, Data}.

%%%===================================================================
%% EIMS WS API
%%%===================================================================

get_user_resource(#jid{user = User, server = Server}) ->
	case ejabberd_sm:get_user_resources(User, Server) of
		[Resource | _] ->
			{ok, Resource};
		[] -> {error, offline}
end.

find_occupant(#state{jid = #jid{} = JID, nick = Nick}, Pkt = #packet{params = #{<<"channel">> := Room}}) ->
	case catch mod_muc_admin:get_room_occupants(Room, ?MUC_HOST) of
		{error, room_not_found} ->
			(packet_error(Pkt))#packet_error{message = <<"channel not found">>};
		Occupants ->
			Users = [case jid:remove_resource(J = jid:decode(Jid)) of
				         JID when Nick == N -> J; %% TODO if other nick?
				         _ -> []
			         end || {Jid, N, _} <- Occupants],
			case Users of
				[#jid{} = J | _] -> {ok, J};
				 [] -> (packet_error(Pkt))#packet_error{message = <<"You are not in the channel">>, data = #{<<"channel">> => Room}} %% TODO enter to channel?
			end
	end.

send_timeout(Pid, Id) ->
	Pid ! {send, #packet_error{id = Id, message = <<"timed_out">>, code = 13888, usIn = 0}}.

is_valid_heartbeat(Interval) ->
	Interval >= ?MIN_HEARTBEAT_INTRVAL andalso Interval =< ?MAX_HEARTBEAT_INTRVAL.
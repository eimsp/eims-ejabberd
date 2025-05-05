-module(eims).
-behaviour(gen_mod).
-compile(export_all).
%% API
-export([]).


-include_lib("logger.hrl").
-include_lib("xmpp/include/xmpp.hrl").
-include_lib("mod_muc_room.hrl").
-include_lib("mod_mam.hrl").
-include("eims.hrl").
-include_lib("translate.hrl").
-include_lib("htmerl/include/htmerl.hrl").

stop() ->
	[supervisor:terminate_child(?MODULE, Worker) || Worker <- [eims_scheduler, eims_ws_client]],
	Pid = whereis(?MODULE),
	unregister(?MODULE),
	exit(Pid, shutdown).

restart() ->
	stop(), start().

start() ->
	supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start(Host, _Opts) ->
	ejabberd_hooks:add(user_send_packet, Host, ?MODULE, user_send_packet, 85),
	ejabberd_hooks:add(filter_packet, fun ?MODULE:filter_packet/1, 120),
	start().

stop(Host) ->
	ejabberd_hooks:delete(user_send_packet, Host, ?MODULE, user_send_packet, 85),
	ejabberd_hooks:delete(filter_packet, fun ?MODULE:filter_packet/1, 120),
	stop().

mod_options(_Host) -> [].

init([]) ->
	application:start(throttle),
	throttle:setup(hservice_rate, 20, per_second),
	create_tables(),
	SupFlags = #{strategy => one_for_one,
		intensity => 1000,
		period => 3600},

	SchedulerChild = #{id => eims_scheduler,
		start => {eims_scheduler, start_link, []},
		restart => permanent,
		shutdown => 2000,
		type => worker,
		modules => [eims_scheduler]},

	WSChild = #{id => eims_ws_client,
		start => {eims_ws_client, start_link, [[{callback, {?MODULE, broadcast_from_bot}}]]},
		restart => permanent,
		shutdown => 2000,
		type => worker,
		modules => [eims_ws_client]},
	[xmpp:register_codec(Mod) || Mod <- [xep0424, xep0425, xmpp_codec_embdim]],
	{ok, {SupFlags, [SchedulerChild, WSChild]}}.

depends(_Host, _Opts) ->
	[].

%%====================================================================
%% Hooks handlers
%%====================================================================
user_send_packet({#message{} = Pkt, C2SState} = _Packet) ->
	Pkt2 = xmpp:decode_els(Pkt), %% TODO in future tag_decorator
	Forbidden = fun() -> send_edit(Pkt, "Message forbidden"), {stop, {drop, C2SState}} end, %% TODO send #stanza_error{} in future
	case lists:keymember(mam_result, 1, Pkt2#message.sub_els) of %% TODO Develop function which will check tag lists
		true -> Forbidden();
		_ ->
			Pkt3 = set_origin_id(Pkt2),
			case xmpp:get_subtag(Pkt3, #bot{}) of
				#bot{hash = Hash} -> %% TODO remove hash in user_receive_packet so that the user doesn't see the hash and can't fake it with the same origin_id
					case xmpp:get_subtag(Pkt3, #origin_id{}) of
						#origin_id{id = Id} ->
							case hash([Id, secret()]) of
								Hash -> {Pkt3, C2SState};
								_ -> Forbidden()
							end;
						_ -> Forbidden()
					end;
				_ -> {Pkt3, C2SState}
			end
	end;
user_send_packet(Packet) ->
	Packet.

filter_packet(#message{from = #jid{luser = <<>>}} = Pkt) -> %% TODO select connected component
	set_origin_id(Pkt); %% add origin_id to xmpp component messages
filter_packet(Pkt) ->
	Pkt.

%% DB API

create_tables() ->
	ejabberd_mnesia:create(?MODULE, eims_storage,
		[{disc_only_copies, [node()]},
			{index, [nick, id, email, system_name, main_account_id, access]},
			{attributes, record_info(fields, eims_storage)}]),
	ejabberd_mnesia:create(?MODULE, eims_cmd,
		[{disc_only_copies, [node()]},
			{index, []},
			{attributes, record_info(fields, eims_cmd)}]),
	mnesia:wait_for_tables([eims_cmd], 10000),
	[case mnesia:dirty_read(eims_cmd, Key) of
		 [#eims_cmd{stats = undefined} = Cmd] ->
			 mnesia:dirty_write(Cmd#eims_cmd{stats = 0});
		 _ -> ok
	 end || Key <- mnesia:dirty_all_keys(eims_cmd)],
	mod_eims_admin:save_cmds(),
	mod_eims_admin:filter_base_cmds().

%% manipulate message API

get_msg_id(#archive_msg{id = Id, packet = #message{} = Pkt}) ->
	case xmpp:get_subtag(Pkt, #fasten_apply_to{}) of
		#fasten_apply_to{id = OriginId} -> {<<"a">>, OriginId};
		_ -> case xmpp:get_subtag(Pkt, #origin_id{}) of
			     #origin_id{id = OriginId} -> {<<"o">>, OriginId};
			     _ -> case xmpp:get_subtag(Pkt, #receipt_response{}) of
				          #receipt_response{id = OriginId} -> {<<"id">>, OriginId};
				          _ -> Id
			          end
		     end
	end;
get_msg_id(#archive_msg{packet = #xmlel{name = <<"message">>} = Pkt} = MamMsg) ->
	get_msg_id(MamMsg#archive_msg{packet = xmpp:decode(Pkt)}).

get_mamsg_id(#message{} = Pkt) ->
	case xmpp:get_subtag(xmpp:decode_els(Pkt), #mam_archived{}) of
		#mam_archived{id = MamId} -> MamId;
		_ -> {error, not_found}
	end.

get_retract_id(OriginId, Server) ->
	case eims_sql:get_rid_by_oid(OriginId, Server) of
		{error, _} -> OriginId;
		RetractId -> RetractId
	end.

get_origin_id_by_rid(RetractId, Server) ->
	case eims_sql:get_oid_by_rid(RetractId, Server) of
		{error, _} -> RetractId;
		OriginId -> OriginId
	end.

get_origin_retract_id(#xmlel{name = <<"message">>} = Pkt) ->
	get_origin_retract_id(xmpp:decode(Pkt));
get_origin_retract_id(#message{from = #jid{lserver = Server}} = Pkt) ->
	case xmpp:get_subtag(Pkt, #receipt_response{}) of
		#receipt_response{id = RetractId} ->
			{get_origin_id_by_rid(RetractId, Server), RetractId};
		_ ->
			#origin_id{id = RetractId} = xmpp:get_subtag(Pkt, #origin_id{}),
			case xmpp:get_subtag(Pkt, #replace{}) of
			     #replace{id = OriginId} ->
				     {OriginId, RetractId};
			    _ -> {RetractId, RetractId}
		     end
	end.

get_origin_id(Id) when is_binary(Id) ->
	Id;
get_origin_id(#archive_msg{id = Id, packet = Pkt}) ->
	get_origin_id(xmpp:decode(Pkt), Id);
get_origin_id(#message{id = Id} = Pkt) ->
	get_origin_id(Pkt, Id);
get_origin_id(#xmlel{name = <<"message">>} = Pkt) ->
	get_origin_id(xmpp:decode(Pkt)).
get_origin_id(#message{id = Id} = Pkt, DefaultId) ->
	Pkt2 = xmpp:decode_els(Pkt),
	case xmpp:get_subtag(Pkt2, #origin_id{}) of
		#origin_id{id = OriginId} -> OriginId;
		_ -> case xmpp:get_subtag(Pkt2, #receipt_response{}) of
			     #receipt_response{id = OrigId} -> OrigId;
			     _ when Id /= <<>> -> Id;
				 _ -> DefaultId
		     end
	end;
get_origin_id(#xmlel{name = <<"message">>} = Pkt, Id) ->
	get_origin_id(xmpp:decode(Pkt), Id).

retract_subels(OriginId) ->
	retract_subels(OriginId, []).
retract_subels(MamMsg, SubEls) ->
	[#fasten_apply_to{id = get_origin_id(MamMsg), sub_els = [#retract_id{}]} | SubEls].

edit_subels(<<>>) ->
	[];
edit_subels(Id) ->
	edit_subels(Id, []).
edit_subels(Id, SubEls) when is_binary(Id) ->
	[#replace{id = Id}, #chatstate{type = active} | SubEls];
edit_subels(#archive_msg{} = MamMsg, SubEls) ->
	edit_subels(get_origin_id(MamMsg), SubEls).

upd_msg(From, To, Id, SubElsFun) ->
	upd_msg(From, To, Id, SubElsFun, fun(Pkt) -> [Pkt] end, []).
upd_msg(From, To, Id, SubElsFun, SubEls) when is_list(SubEls) ->
	upd_msg(From, To, Id, SubElsFun, fun(Pkt) -> [Pkt] end, SubEls);
upd_msg(From, To, Id, SubElsFun, UpdFun) when is_function(UpdFun) ->
	upd_msg(From, To, Id, SubElsFun, UpdFun, []).
upd_msg(_From, _To, {error, _} = Err, _SubElsFun, _UpdFun, _SubEls) ->
	Err;
upd_msg(<<_/integer, _/binary>> = F, <<_/integer, _/binary>> = T, Id, SubEls, UpdFun, SubEls2) ->
	upd_msg(jid:decode(F), jid:decode(T), Id, SubEls, UpdFun, SubEls2);
upd_msg(#jid{luser = _Room, lserver = _RoomHost} = From, #jid{} = To,
	ArcMsg = #archive_msg{id = MamId, packet = #message{} = Pkt}, SubElFun, UpdFun, SubEls) ->
	UpdFun(Pkt#message{id = MamId, from = From, to = To,
		sub_els = ?MODULE:SubElFun(ArcMsg#archive_msg{packet = xmpp:encode(Pkt)}, SubEls)});
upd_msg(From, #jid{} = To, IdFun, SubEls, UpdFun, SubEls2) when is_function(IdFun)->
	upd_msg(From, To, IdFun(), SubEls, UpdFun, SubEls2);
upd_msg(#jid{luser = Room, lserver = RoomHost} = From, #jid{} = To, Id, SubEls, UpdFun, SubEls2) ->
	ArcMsg = eims_db:get_mam_msg_by_id({Room, RoomHost}, Id),
	upd_msg(From, To, ArcMsg, SubEls, UpdFun, SubEls2).

send_edit(#message{body = [#text{data = Text}]} = Pkt) ->
	send_edit(Pkt, Text, bot).
send_edit(Pkt, Text) ->
	send_edit(Pkt, Text, bot).
send_edit(Pkt, {Text, Entities}, bot) ->
	send_edit(Pkt, Text, [bot_tag(), #message_entities{items = Entities}]);
send_edit(Pkt, Text, bot) ->
	send_edit(Pkt, Text, [bot_tag()]);
send_edit(#message{to = undefined}, Text, _) ->
	Text;
send_edit(#message{sub_els = []} = Pkt, Text, SubEls) ->
	send_edit(set_origin_id(Pkt#message{body = [#text{data = <<"dummy">>}]}), Text, SubEls);
send_edit(#message{type = Type, from = From, to = To, sub_els = SubEls} = Pkt, UpdMsgFun, SubEls2) when is_function(UpdMsgFun) ->
	{_UpdFun, _LastMsgFun, SendFun} = occupant_funs(To, From, UpdMsgFun),
	NoStore = case Type of chat -> [#hint{type = 'no-store'}]; _ -> [] end,
	upd_msg(To, From, #archive_msg{packet = Pkt#message{sub_els = SubEls}}, edit_subels, SendFun, SubEls2 ++ NoStore);
send_edit(#message{} = Pkt, Text, SubEls) ->
	send_edit(Pkt, fun(P) -> P#message{body = [#text{data = iolist_to_binary(Text)}]} end, SubEls);
send_edit(_, Text, _) ->
	Text.

send_retract(#archive_msg{packet = #xmlel{name = <<"message">>} = Pkt} = MamMsg) ->
	send_retract(MamMsg#archive_msg{packet = xmpp:decode(Pkt)});
send_retract(#archive_msg{packet = #message{from = #jid{} = From, to = #jid{} = To} = _Pkt, nick = Nick} = MamMsg) ->
	{BroadcastSendFun, _, _SendFun} = occupant_funs(To, From, Nick),
	upd_msg(To, From, MamMsg, retract_subels, BroadcastSendFun).
%%	Id = upd_msg(To, From, MamMsg, retract_subels, BroadcastSendFun).
%%	delete_from_history_by_id(Room, RoomHost, Host, [Id]),
%%	remove_mam_msg_by_ids(Room, RoomHost, [Id]).


set_origin_id(#message{id = <<>>} = Pkt) ->
	set_origin_id(Pkt#message{id = gen_uuid()});
set_origin_id(#message{} = Pkt) ->
	Pkt2 = xmpp:decode_els(Pkt),
	case not xmpp:has_subtag(Pkt2, #origin_id{}) andalso
		not xmpp:has_subtag(Pkt2, #receipt_response{}) andalso
		not xmpp:has_subtag(Pkt2, #fasten_apply_to{}) of
		true -> xmpp:set_subtag(xmpp:set_subtag(Pkt2, #origin_id{id = gen_uuid()}), #chatstate{type = active});
		_ -> Pkt
	end.

hash_packet(#message{} = Pkt) ->
	case xmpp:get_subtag(Pkt, #bot{}) of
		#bot{hash = <<>>} = Bot ->
			case xmpp:get_subtag(Pkt, #origin_id{}) of
				#origin_id{id = Id} ->
					xmpp:set_subtag(Pkt, Bot#bot{hash = hash([Id, secret()])});
				_ ->
					Id = gen_uuid(),
					xmpp:set_subtag(xmpp:set_subtag(Pkt, Bot#bot{hash = hash([Id, secret()])}), #origin_id{id = Id})
			end;
		_ -> Pkt
	end.

%% call occupant_funs so as not to call mod_muc_admin:get_room_occupants several times in different places
occupant_funs(To, From, Nick) when is_binary(Nick) ->
	occupant_funs(To, From, fun(P) -> P end, fun(_) -> Nick end);
occupant_funs(#jid{} = From, #jid{} = To, UpdMsgFun) ->
	NickFun =
		fun(Occupants) ->
			case lists:keyfind(jid:encode(To), 1, Occupants) of
				false -> <<>>;
				{_, Nick, _} -> Nick
			end
		end,
	occupant_funs(From, To, UpdMsgFun, NickFun).
occupant_funs(#jid{luser = Room, lserver = RoomHost} = From, #jid{} = To, UpdMsgFun, NickFun) ->
	Occupants = mod_muc_admin:get_room_occupants(Room, RoomHost),
	Nick = NickFun(Occupants),
	FullFrom = jid:replace_resource(From, Nick), %% add nick to room resource
	SendFun =
		fun(#message{id = Id} = Pkt) ->
			Pkt2 = hash_packet(UpdMsgFun(Pkt)),
			route(Pkt2#message{from = FullFrom, to = To}), Id
		end,
	BroadcastSendFun =
		fun(#message{id = Id} = Pkt) ->
			Pkt2 = hash_packet(UpdMsgFun(Pkt)),
			[route(Pkt2#message{from = FullFrom, to = jid:decode(T)}) || {T, _, _} <- Occupants],
			Id
		end,
	LastMsgFun = fun() -> eims_db:get_last_msg(FullFrom) end,
	{BroadcastSendFun, LastMsgFun, SendFun}.

subscriber_nicks(#state{muc_subscribers = MucSubs}) ->
	subscriber_nicks(MucSubs);
subscriber_nicks(#muc_subscribers{subscriber_nicks = Nicks}) ->
	Nicks.
subscriber_nicks(Name, Service) ->
	{_, #state{muc_subscribers = MucSubscribers}} = eims:get_state(Name, Service),
	subscriber_nicks(MucSubscribers).

subscriber_nick(JID, Name, Service) ->
	subscriber_nick(JID, subscribers(Name, Service)).

subscriber_nick(JID, #state{muc_subscribers = MucSubs}) ->
	subscriber_nick(JID, MucSubs);
subscriber_nick(JID, #muc_subscribers{subscribers = SubJids}) ->
	subscriber_nick(JID, SubJids);
subscriber_nick(JID, #{} = SubJids) ->
	LJID = jid:tolower(jid:remove_resource(JID)),
	case SubJids of
		#{LJID := #subscriber{nick = N}} -> N;
		_ -> <<>>
	end.

subscriber_jid(Nick, Name, Service) ->
	subscriber_jid(Nick, subscriber_nicks(Name, Service)).
subscriber_jid(Nick, #state{muc_subscribers = MucSubs}) ->
	subscriber_jid(Nick, MucSubs);
subscriber_jid(Nick, #muc_subscribers{subscriber_nicks = SubNicks}) ->
	subscriber_jid(Nick, SubNicks);
subscriber_jid(Nick, #{} = SubNicks) ->
	Host = eims:host(),
	case SubNicks of
		#{Nick := [{User, Host, _}]} -> jid:make(User, Host);
		_ -> <<>>
	end.

muc_subscribers(#state{muc_subscribers = MucSubs}) -> MucSubs.
muc_subscribers(Name, Service) ->
	{_Pid, #state{muc_subscribers = MUCSubscribers}} = get_state(Name, Service),
	MUCSubscribers.
subscribers(Name, Service) ->
	subscribers(muc_subscribers(Name, Service)).
subscribers(#muc_subscribers{subscribers = Subs}) -> Subs.

subscribe(User, Room, Nick) ->
	subscribe(User, Room, Nick, []).
subscribe(#jid{lserver = Host} = User, Conf, Nick, Nodes) ->
	subscribe(Host, User, Conf, Nick, Nodes).
subscribe(Host, User, #jid{luser = Room, lserver = Server}, Nick, Nodes) ->
	case mod_muc:unhibernate_room(Host, Server, Room) of
		error -> {error, room_not_found};
		{ok, Pid} = P ->
			BeerUser = jid:remove_resource(User),
			mod_muc_room:subscribe(Pid, BeerUser, Nick, Nodes),
			P
	end.
unsubscribe(#jid{lserver = Host} = User, Confer) ->
	unsubscribe(Host, User, Confer).
unsubscribe(Host, User, #jid{luser = Room, lserver = Server}) ->
	case mod_muc:unhibernate_room(Host, Server, Room) of
		{error, _Reason} = Err -> Err;
		{ok, Pid} ->
			BareFrom = jid:remove_resource(User),
			case mod_muc_room:is_subscribed(Pid, BareFrom) of
				{true, _, _} -> mod_muc_room:unsubscribe(Pid, BareFrom);
				_ -> ok
			end
	end.

get_room_nick(Jid, Name, Service) ->
	get_room_nick(Jid, mod_muc_admin:get_room_occupants(Name, Service)).
get_room_nick(#jid{} = JID, #state{users = Users}) ->
	LJID = jid:tolower(JID),
	case Users of
		#{LJID := #user{nick = Nick}} -> Nick;
		_ -> <<>>
	end;
get_room_nick(#jid{} = JID, Occupants) ->
	get_room_nick(jid:encode(JID), Occupants);
get_room_nick(Jid, Occupants) when is_binary(Jid) ->
	case lists:keyfind(Jid, 1, Occupants) of
		{_, Nick, _} -> Nick;
		_ -> throw({error, jid_not_found_in_room})
	end.

room_route(Pkt, Nick) ->
	room_route(Pkt, Nick, false).
room_route(Pkt, Nick, Store) ->
	room_route(Pkt, Nick, Store, []).
room_route(#message{from = From, to = To, id = OrigId} = Pkt, Nick, Store, SubEls2) ->
	case subscribe(From, To, Nick) of
		{error, Reason} = Err ->
			?DEBUG("ERROR: invalid subscribe ~p to ~p\nreason: ~p", [From, To, Reason]),
			Err;
		{ok, Pid} ->
			StoreHint = case Store of false -> [#hint{type = 'no-store'}]; _ -> [] end,
			Pkt2 = xmpp:set_els(Pkt, edit_subels(OrigId) ++ StoreHint ++ SubEls2 ++ [#origin_id{id = gen_uuid()}]),
			mod_muc_room:route(Pid, hash_packet(Pkt2))
	end.

send_msg(#message{id = Id} = Pkt) ->
	send_msg(Pkt, Id).
send_msg(#message{from = From, to = #jid{luser = Room, lserver = RoomHost}} = Pkt, OID) ->
	case lists:keyfind(jid:encode(From), 1, mod_muc_admin:get_room_occupants(Room, RoomHost)) of
		{_, Nick, _} ->
			room_route(Pkt, Nick, OID);
		_ -> {error, nick_not_found}
	end.

%% History API
select_history({Room, Server}) ->
	select_history({Room, Server}, []).
select_history({Room, Server}, Query) ->
	select_history(jid:make(Room, Server), Query, 20).
select_history({Room, Server}, Query, Max) ->
	select_history(jid:make(Room, Server), Query, Max);
select_history(#jid{luser = Room, lserver = Server} = JID, Query, Max) ->
	Host = ejabberd_router:host_of_route(Server),
	{_, #state{history = History}} = eims:get_state(Room, Server),
	{Msgs, _, _} = mod_mam:select(Host, JID, JID,
		Query, #rsm_set{max = Max}, {groupchat, any, #state{config = #config{mam = false},
			history = History}}, only_messages),
	[Msg || {_, _, #forwarded{sub_els = [Msg]}} <- Msgs].

edit_history_msg(Room, RoomHost, Host, Id, NewText) ->
	UpdFun =
		case is_integer(Id) of
			true ->
				fun({_, #message{meta = #{stanza_id := Id2}, body = [#text{} = Text]} = Pkt, _, _, _} = R) when Id2 == Id ->
					setelement(2, R, Pkt#message{body = [Text#text{data = NewText}]});
					(R) -> R
				end;
			_ ->
				fun({_, #message{body = [#text{} = Text]} = Pkt, _, _, _} = R) ->
					case xmpp:get_subtag(Pkt, #origin_id{}) of
						#origin_id{id = Id} ->
							setelement(2, R, Pkt#message{body = [Text#text{data = NewText}]});
						_ -> R
					end
				end
		end,
	upd_history(Room, RoomHost, Host, fun(_) -> true end, UpdFun).

get_state(Name, Service) ->
	{ok, Pid} =  mod_muc:unhibernate_room(?HOST, Service, Name),
	{ok, State} = mod_muc_room:get_state(Pid),
	{Pid, State}.

change_state(Pid, State) ->
	try p1_fsm:sync_send_all_state_event(Pid, {change_state, State})
	catch _:{timeout, {p1_fsm, _, _}} ->
		{error, timeout};
		_:{_, {p1_fsm, _, _}} ->
			{error, not_found}
	end.

purge_by_nick(#jid{luser = Room, lserver = RoomHost, lresource = Nick} = _From) -> %% TODO maybe get resource (?)
	[send_retract(MamMsg) || #archive_msg{} = MamMsg <- eims_db:get_mam_by_nick({Room, RoomHost}, Nick)];
purge_by_nick(<<_/integer,_/binary>> = RoomNick) ->
	purge_by_nick(jid:decode(RoomNick)).

filter_room_history(Room, RoomHost, Host, FilterFun) ->
	upd_history(Room, RoomHost, Host, FilterFun, fun(Obj) -> Obj end).

clear_room_history(Room, RoomHost, _Host) -> %% TODO remove Host arg
	{Pid, State} = {_, #state{history = History}} = get_state(Room, RoomHost),
	NewState = State#state{history = History#lqueue{queue = p1_queue:new()}},
	change_state(Pid, NewState).

clear_room_history(Room, RoomHost, Host, #jid{luser = User, lserver = Server}) ->
	filter_room_history(Room, RoomHost, Host,
		fun({_,#message{from = #jid{luser = User2, lserver = Server2}},_,_,_})
			-> {User, Server} /= {User2, Server2}
		end);
clear_room_history(Room, RoomHost, Host, PeerNick) ->
	filter_room_history(Room, RoomHost, Host,fun({PN,_,_,_,_}) -> PN /= PeerNick end).

delete_from_history_by_id(Room, RoomHost, Host, [H| _] = Ids) when is_integer(H) ->
	filter_room_history(Room, RoomHost, Host,
		fun({_,#message{meta = #{stanza_id := Id}},_,_,_}) ->
			not lists:member(Id, Ids)
		end);
delete_from_history_by_id(Room, RoomHost, Host, [OriginId | _] = OriginIds) when is_binary(OriginId) ->
	filter_room_history(Room, RoomHost, Host,
		fun({_,#message{} = Pkt,_,_,_}) ->
			case xmpp:get_subtag(Pkt, #origin_id{}) of
				#origin_id{id = Id} ->
					not lists:member(Id, OriginIds);
				_ ->
					true
			end
		end).

filter_history(Room, RoomHost, Host, FilterFun) ->
	filter_history(Room, RoomHost, Host, FilterFun, fun(R) -> R end).
filter_history(Room, RoomHost, _Host, FilterFun, UpdFun) -> %% TODO remove Host arg
	{Pid, State} = {_, #state{history = #lqueue{queue = Q}}} = get_state(Room, RoomHost),
	{[UpdFun(R) || R <- p1_queue:to_list(Q), FilterFun(R)], Pid, State}.

upd_history(Room, RoomHost, Host, FilterFun, UpdFun) ->
	{L, Pid, #state{history = History} = State} = filter_history(Room, RoomHost, Host, FilterFun, UpdFun),
	change_state(Pid, State#state{history = History#lqueue{queue = p1_queue:from_list(L)}}).

%% API utils
binary_join([], _Sep) -> <<>>;
binary_join([Part], _Sep) -> Part;
binary_join(List, Sep) ->
	lists:foldr(fun (A, B) ->
		if bit_size(B) > 0 -> <<A/binary, Sep/binary, B/binary>>; true -> A end end, <<>>, List).

split(Subject, Deep) ->
	split(Subject, Deep, []).
split(Subject, Deep, Default) ->
	split(Subject, Deep, Default, <<" ">>).
split(Subject, Deep, Default, Pattern) ->
	split(Subject, Deep, Default, Pattern, []).
split(_Subject, 0, _Default, _Pattern, Acc) ->
	Acc;
split(Subject, Deep, #{plane := Default}, Pattern, Acc) ->
	split(Subject, Deep, Default, Pattern, Acc);
split(Subject, Deep, #{json := #{} = DefaultJson}, Pattern, Acc) ->
	split(Subject, Deep, [jiffy:encode(DefaultJson)], Pattern, Acc);
split(Subject, 1, _Default, _Pattern, Acc) ->
	Acc++[Subject];
split(Subject, Deep, Default, Pattern, Acc) ->
	Default2 = case length(Default) < Deep of true -> Default; _ -> tl(Default) end,
	case [list_to_binary(string:strip(binary_to_list(S))) || S <- binary:split(Subject, Pattern)] of
		[H | T] when T == []; T == [<<>>] ->
			Acc ++ [H] ++ lists:sublist(Default2, Deep-1);
		[H, T] -> split(T, Deep-1, Default2, Pattern, Acc++[H])
	end.

%% let's use auth_http fields, we will not enable auth_http anyway, so reuse its settings only
%% and lets put host -> <eims api_host> into a map
%% auth_opts:
%%    connection_opts:
%%      "localhost": "localhost:8082"
%%      "chattest.hservice.com": "www.hservice.com"
connection_opts() ->
	maps:from_list(proplists:get_value(connection_opts, ejabberd_option:auth_opts())).


get_from_private(#jid{luser = User, lserver = Host}) ->
	case mod_private:get_data(User, Host, [{?NS_EIMS, #xmlel{name = <<"eims">>}}]) of
		[#xmlel{name = <<"eims">>}=Data|_] -> Data;
		E -> E
	end.

%%get_eims_data(#jid{luser = User, lserver = Host}) ->
%%	case mnesia:dirty_read(eims_storage, {User, Host}) of
%%		#eims_storage{} = Data -> get_eims_data(Data); %%TODO this code will never be called because dirty_read returns list of records
%%		E -> E
%%	end;
%%get_eims_data(#eims_storage{} = DS) ->
%%	maps:from_list(lists:zip([atom_to_binary(F) || F <- record_info(fields, eims_storage)], tl(tuple_to_list(DS)))).

set_eims_data(#jid{} = Jid, EIMSData) ->
	mod_private:set_data(Jid, [{?NS_EIMS, EIMSData}]).

set_eims_element({Name, CData}, EIMSData = #xmlel{children = Subels}) ->
	Subels2 = lists:keystore(Name, 2, Subels, #xmlel{name = Name, children = [{xmlcdata, CData}]}),
	EIMSData#xmlel{children = Subels2}.

get_eims_element(Name, #xmlel{children = Subels}) ->
	case lists:keyfind(Name, 2, Subels) of
		#xmlel{children = [{xmlcdata, El}]} -> El;
		_ -> []
	end.

check_sync_iserv(Fun) ->
	check_sync_iserv(Fun, 3).
check_sync_iserv(_Fun, 0) ->
	{error, overload};
check_sync_iserv(Fun, Count) ->
	case throttle:check(hservice_rate, hservice_request) of
		rate_not_set -> {error, rate_not_set};
		{ok, _, _} -> Fun();
		{limit_exceeded, 0, DelayTime} ->
			timer:sleep(round(DelayTime*1000)+1),
			check_sync_iserv(Fun, Count-1)
	end.

drop_tokens(Jid) ->
	set_tokens(Jid, [], []).
set_token_expired_time(#jid{} = Jid, StartTime) ->
	set_tokens(Jid, StartTime, undefined).
set_tokens(#jid{luser = User, lserver = Host}, Data, TRef) ->
	eims_scheduler:call({set_data, {User, Host}, Data, TRef}).

get_tokens(User, Host) ->
	get_tokens(jid:make(User, Host)).
get_tokens(#jid{luser = User, lserver = Host}) ->
	eims_scheduler:call({get_data, {User, Host}}).

send_delay_check({Jid, Data}, Fun, Interval) when is_binary(Jid) ->
	send_delay_check({jid:from_string(Jid), Data}, Fun, Interval);
send_delay_check({#jid{luser = User, lserver = Host} = Jid, Data}, Fun, Interval) ->
	TRef = erlang:send_after(Interval, eims_scheduler,
		{eims_send, {User, Host}, check_iserv_decorator({Jid, Data}, Fun)}),
	set_tokens(Jid, Data, TRef).

check_iserv_decorator({#jid{luser = User, lserver = Host}, _} = FullData, Fun) ->
	fun(Data) ->
		case ejabberd_sm:get_user_resources(User, Host) of
			[] -> ok;
			_ ->
				case throttle:check(hservice_rate, hservice_request) of
					{ok, _, _} -> Fun(Data);
					{limit_exceeded, 0, DelayTime} ->
						?dbg("limit_exceeded", []),
						%% try send after limit exceeded
						send_delay_check(FullData, Fun, DelayTime + 100)
				end
		end
	end.

%% Date and time
sys_time() ->
	os:system_time(millisecond).
time_to_string({{Year, Month, Day}, {Hour, Min, Sec}}, Zone) ->
	io_lib:format("~s, ~s ~s ~w ~s:~s:~s ~s", [day(Year, Month, Day), mk2(Day), month(Month), Year, mk2(Hour), mk2(Min), mk2(Sec), Zone]).
local_time_as_gmt(LocalTime) ->
	S = time_to_string(erlang:localtime_to_universaltime(LocalTime), "GMT"),
	lists:flatten(string:join(string:lexemes(S, " ,:"), "_")).
mk2(I) when I < 10 -> [$0 | integer_to_list(I)];
mk2(I) -> integer_to_list(I).
day(Year, Month, Day) -> int_to_wd(calendar:day_of_the_week(Year, Month, Day)).
month(M) -> lists:nth(M, ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]).
int_to_wd(Wd) -> lists:nth(Wd, ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]).
ts_to_datetime(Timestamp) ->
	{{Year, Month, Day}, {Hour, Minute, Second}} = calendar:system_time_to_universal_time(Timestamp, millisecond),
	iolist_to_binary(io_lib:format("~4..0w-~2..0w-~2..0w ~2..0w:~2..0w:~2..0w",[Year,Month,Day,Hour,Minute,Second])).
now_to_timestamp({MSec, Sec, USec}) ->
	(MSec * 1000000 + Sec) * 1000000 + USec.

timestamp_to_now(I) ->
	Head = I div 1000000,
	USec = I rem 1000000,
	MSec = Head div 1000000,
	Sec = Head rem 1000000,
	{MSec, Sec, USec}.

format_utc_timestamp(TS) ->
	{{Year,Month,Day},{Hour,Minute,Second}} =
		calendar:now_to_universal_time(TS),
	lists:flatten(io_lib:format("~4w-~2..0w-~2..0wT~w:~2..0w:~2..0wZ", [Year,Month,Day,Hour,Minute,Second])).


%% JSON
decode_json(<<>>, _) -> #{};
decode_json(<<" ">>, _) -> #{};
decode_json(<<"\r\n">>, _) -> #{};
decode_json(Data, Tag) ->
	case catch jiffy:decode(Data, [return_maps]) of
		#{Tag := Result} -> Result;
		_                -> ?err("Invalid json: ~p", [Data]), #{}
	end.
decode_json(Data) ->
	decode_json(Data, <<"result">>).

%% User account
gen_summary(Nick, JidNode) ->
	Id = sys_time(), LowNick = string_to_lower(Nick),
	PrivateData = #{
		%% private data is becomes sorted in storage, space is always first
		%% prepend "whale." to nicks from EIMS, nick here:
		<<" ">> =>  Nick,
		<<"jid_node">> =>  JidNode,
		<<"nick">> => Nick, %% nick
		<<"email">> => <<>>,
		<<"system_name">> => LowNick,
		<<"id">> => Id,
		<<"main_account_id">> => Id,
		<<"main_system_name">> => JidNode,
		<<"main_email">> => <<>>,
		<<"roles">> => [<<"none">>]
	},
	VirtualHost = host(),
	{PrivateData, #eims_storage{
								jid = {JidNode, VirtualHost},
								nick = Nick,
								id = Id,
								system_name = LowNick,
								main_account_id = Id,
								main_system_name= JidNode}}.

get_all_accounts(#eims_storage{id = 0, jid = #jid{luser = User, lserver = Host}}) ->
	case mnesia:dirty_read(eims_storage, {User, Host}) of
		[#eims_storage{id = Id} = UserStorage] when is_integer(Id), Id > 0 ->
			get_all_accounts(UserStorage);
		[] -> [];
		[UserStorage] ->
			?dbg("error: invalid_storage data: ~p", [UserStorage]),
			[UserStorage]
	end;
get_all_accounts(#eims_storage{main_account_id = MainId}) ->
	mnesia:dirty_index_read(eims_storage, MainId, main_account_id).

is_ejuser(<<"whale.", _/binary>>) -> false;
is_ejuser(_) -> true.

-spec get_permission_level(jid(), binary()) -> boolean().
get_permission_level({U, S}, [_|_]=Rs)->
	Acl = acl:match_rule(S, eims_admin, #{usr => {U, S, <<>>}}),
	case mnesia:dirty_read(eims_storage, {U, S}) of
		_ when Acl == allow -> true;
		[#eims_storage{roles = Roles}] ->
			lists:any(fun(B) -> B end, [lists:member(R, Roles) || R <- Rs]);
		_ -> false
	end.

get_jid_by_priv_data(<<_/integer, _/binary>> = NickJid, {Room, RoomHost} = Conference) ->
	case catch jid:decode(NickJid) of
		#jid{luser = <<_/integer, _/binary>> = U, lserver = S} = Jid ->
			case mnesia:dirty_read(eims_storage, {U, S}) of
				[#eims_storage{jid = {U, S}} = UserStorage] ->
					UserStorage#eims_storage{jid = jid:remove_resource(Jid)};
				_ -> {error, jid_not_found}
			end;
		_ ->
			case catch binary_to_integer(NickJid) of
				Id when is_integer(Id) ->
					case mnesia:dirty_index_read(eims_storage, Id, #eims_storage.id) of
						[#eims_storage{jid = {U, S}} = UserStorage] ->
							UserStorage#eims_storage{jid = jid:make(U, S, <<>>)};
						[] -> {error, jid_not_found}
					end;
				_ ->
					case mnesia:dirty_index_read(eims_storage, NickJid, #eims_storage.nick) of
						[#eims_storage{jid = {U, S}} = UserStorage] ->
							UserStorage#eims_storage{jid = jid:make(U, S, <<>>)};
						[] ->
							case lists:keyfind(NickJid, 2, mod_muc_admin:get_room_occupants(Room, RoomHost)) of
								{JidRes, _Nick, _} ->
									Jid = #jid{luser = U, lserver = S} = jid:remove_resource(jid:decode(JidRes)),
									Is_EjUser = is_ejuser(U),
									case get_storage_by_field({U, S}) of
										#eims_storage{} = UStor -> UStor#eims_storage{jid = Jid};
										_ when not Is_EjUser -> {error, jid_not_found};
										_ -> {_PrivateData, UStorage} = gen_summary(NickJid, U),
											%ok = mnesia:dirty_write(UStorage),
											%ejabberd_auth_store_private(PrivateData, U),
											UStorage#eims_storage{jid = Jid}
									end;
								false ->
									case eims_db:get_last_msg(Conference, NickJid) of
										#archive_msg{bare_peer = {U1, S1, _}, nick = Nick} ->
											Jid = jid:make(U1, S1),
											Is_EjUser = is_ejuser(U1),
											case get_storage_by_field({U1, S1}) of
												#eims_storage{} = UStor ->
													UStor#eims_storage{jid = Jid};
												_ when not Is_EjUser -> {error, jid_not_found};
												_ -> {_PrivateData, UStorage} = gen_summary(Nick, U1),
													ok = mnesia:dirty_write(UStorage),
													%ejabberd_auth_store_private(PrivateData, U),
													UStorage#eims_storage{jid = Jid}
											end;
										E -> ?dbg("get_jid_by_nick: ~s: ~p", [NickJid, E]),
											{error, jid_not_found}
									end
							end
					end
			end
	end;

get_jid_by_priv_data(NickJid, Conference) ->
	?dbg("get_jid_by_nick: ~p not found in ~p", [NickJid, Conference]),
	{error, jid_not_found}.

get_storage_by_field(#jid{luser = User, lserver = Server}) ->
	get_storage_by_field({User, Server});
get_storage_by_field({_, _} = Jid) ->
	get_storage_by_field(Jid, #eims_storage.jid).
get_storage_by_field(Field, Attr) ->
	{Fun, Args} = case Attr of #eims_storage.jid -> {dirty_read, [Field]}; _ -> {dirty_index_read, [Field, Attr]} end,
	case apply(mnesia, Fun, [eims_storage | Args]) of
		[#eims_storage{jid = {U, S}} = UserStorage] -> %% TODO maybe more then one element of list
			UserStorage#eims_storage{jid = jid:make(U, S)};
		[] -> {error, jid_not_found}
	end.

jid_or_nick(JidOrNick) when is_binary(JidOrNick) ->
	case catch jid:from_string(JidOrNick) of
		#jid{luser = <<_/integer, _/binary>>} = Jid -> Jid;
		_ -> JidOrNick
	end.

string_to_usr(JID) when is_binary(JID) ->
	case  jid:string_to_usr(JID) of
		{<<>>, User, _} -> {User, host()};
		{User, Server, _} -> {User, Server}
	end.

gen_uuid() ->
	list_to_binary(uuid:uuid_to_string(uuid:get_v4())).
gen_uuid(TimeStamp) ->
	B1 = integer_to_binary(TimeStamp),
	B2 = gen_uuid(),
	<<B1/binary, "-", B2/binary>> .
gen_nonce() ->
	gen_nonce(10).
gen_nonce(Length) ->
	get_random_string(Length, "1234567890abcdefghijklmnopqrstuvwxyz").
gen_nonce_bin(Length) ->
	iolist_to_binary(gen_nonce(Length)).
gen_nonce_bin() ->
	gen_nonce_bin(10).
get_random_string(Length, AllowedChars) ->
	[lists:nth(rand:uniform(length(AllowedChars)), AllowedChars) || _ <- lists:seq(1, Length)].

migrate() ->
	  %% Default path for the release in this code
		{ok,[Dir|_]} = application:get_env(ejabberd, migresia, {ok,[{rel_relative_dir,"../../priv/migrations/"}]}),
	migresia:migrate(Dir).

gen_hash_base64(Args) ->
	Data = iolist_to_binary(Args ++ [ejabberd_option:sql_password()]),
	base64:encode(crypto:hash(md5, Data)).

check_hash(Hash, Args) ->
	case gen_hash_base64(Args) of
		Hash -> true;
		_ -> false
	end.
	
tag_decorator([], Data, Mod, Fun) ->
	fun() -> Mod:Fun(Data) end;
tag_decorator([El | TEls], [Pkt | _] = Data, Mod, Fun) ->
	case xmpp:get_subtag(Pkt, El) of
		false -> tag_decorator(TEls, Data, Mod, Fun);
		Tag -> fun() -> Mod:Fun(Tag, Data) end
	end.

-spec unwrap_mucsub_message(xmpp_element()) -> message() | false.
unwrap_mucsub_message(#message{} = OuterMsg) ->
	case xmpp:get_subtag(OuterMsg, #ps_event{}) of
		#ps_event{
			items = #ps_items{
				node = Node,
				items = [
					#ps_item{
						sub_els = [InnerMsg]} | _]}}
			when Node == ?NS_MUCSUB_NODES_MESSAGES;
			Node == ?NS_MUCSUB_NODES_SUBJECT ->
			case xmpp:decode(InnerMsg) of
				#message{} = Msg -> Msg;
				_ -> false
			end;
		_ ->
			false
	end;
unwrap_mucsub_message(_Packet) ->
	false.


%% Utils
m_reload(Path) ->
	% Default Path = "src/eims",
	[ begin [M, _] = string:split(Module, "."), c:c(list_to_atom(M))  end ||
	{ok, List} <- [file:list_dir(Path)], Module<-List ].


mod_doc() ->
	#{desc => ?T("EIMS utils"), opts => []}.

%% test API
run_test() ->
	run_test(admin_eims_SUITE, []).
run_test(Suite) ->
	run_test(Suite, []).
run_test(Suite, Testcase) when is_atom(Testcase) ->
	run_test(Suite, [Testcase]);
run_test(Suite, Testcases) when is_atom(Suite) ->
	case application:get_env(ejabberd, eims-ejabberd_path, []) of
		[] -> ?dbg("ERROR: eims-ejabberd_path not found. Set eims-ejabberd_path in ejabberd section of sys.config", []),
			{error, invalid_eims-ejabberd_path};
		EIMSPath ->
			ct:run_test(
				[{testcase, T} || T <- Testcases] ++
				[{suite, Suite},
					{dir, filename:join(EIMSPath, "test")},
					{include, ["_build/dev/lib/escalus", "include"]},
					{config, filename:join(EIMSPath, "test/test.config")}])
	end.

wait_for_result(Fun, WaitedResult) ->
	wait_for_result(Fun, WaitedResult, 20, 100).
wait_for_result(Fun, _WaitedResultFun, 0, _) ->
	{error, wait_timout, Fun()};
wait_for_result(Fun, WaitedResultFun, Counter, Interval) when is_function(WaitedResultFun) ->
	Result = Fun(),
	case WaitedResultFun(Result) of
		true -> Result;
		_ ->
			timer:sleep(Interval),
			wait_for_result(Fun, WaitedResultFun, Counter-1, Interval)
	end;
wait_for_result(Fun, WaitedResult, Counter, Interval) ->
	case Fun() of
		WaitedResult -> WaitedResult;
		_ ->
			timer:sleep(Interval),
			wait_for_result(Fun, WaitedResult, Counter-1, Interval)
	end.


wait_for_list(Fun) ->
	wait_for_list(Fun, 0).
wait_for_list(Fun, Length) ->
	wait_for_list(Fun, Length, 20, 100).
wait_for_list(Fun, Length, Counter, Interval) when is_integer(Counter), is_integer(Interval), is_integer(Length)->
	PredFun =
		fun(Arg) when is_list(Arg), length(Arg) == Length -> true;
			(_Arg) -> false
		end,
	wait_for_result(Fun, PredFun, Counter, Interval).

host() ->
	hd(ejabberd_option:hosts()).

hservice_host() ->
	maps:get(host(), connection_opts()).

muc_host() ->
	mod_muc_opt:host(host()).

hash(Data) ->
	hash(Data, 16).
hash(Data, Size) when is_list(Data) ->
	hash(iolist_to_binary(Data), Size);
hash(Data, Size) when is_binary(Data) ->
	binary:part(base64:encode(crypto:hash(md5, Data)), 0, Size).

%% upload API
-spec make_user_string(jid()) -> binary().
make_user_string(#jid{lserver = Host} = User) ->
	JIDinURL = mod_http_upload_opt:jid_in_url(Host),
	make_user_string(User, JIDinURL).

-spec make_user_string(jid(), sha1 | node) -> binary().
make_user_string(#jid{luser = U, lserver = S}, sha1) ->
	str:sha(<<U/binary, $@, S/binary>>);
make_user_string(#jid{luser = U}, node) ->
	replace_special_chars(U).

-spec replace_special_chars(binary()) -> binary().
replace_special_chars(S) ->
	re:replace(S, <<"[^\\p{Xan}_.-]">>, <<$_>>,
		[unicode, global, {return, binary}]).

%% helper API
bot_nick() ->
	gen_mod:get_module_opt(global, mod_eims_admin, bot_nick).
bot_component() ->
	gen_mod:get_module_opt(global, mod_eims_admin, bot_component).

bot_tag() ->
	bot_tag(bot_nick()).
bot_tag(Nick) ->
	#bot{nick = Nick}.

increment_stats(#cmd{acl = all, name = Name, context = #message{from = #jid{luser = <<"whale.", _/binary>>}}, custom = false} = Cmd) ->
	case mnesia:dirty_read(eims_cmd, Name) of
		[#eims_cmd{type = base, stats = Stats, acl = all} = EIMSCmd] ->
			mnesia:dirty_write(EIMSCmd#eims_cmd{stats = Stats + 1}), Cmd;
		_ -> Cmd
	end;
increment_stats(Cmd) ->
	Cmd.

retract_upload(Pkt = #message{from = From}, #message{type = Type, body = [#text{data = Body}]} = RetractedPkt) ->
	Cmd = lists:keyfind(?file_rm, #cmd.name, mod_eims_admin:cmds()),
	Bodies =
		case xmpp:get_subtag(RetractedPkt, #message_upload{}) of
			#message_upload{body = [_ | _]= Bs} ->
				[Url || #message_upload_body{url = Url} <- Bs];
			_ -> [Body]
		end,
	[case Type of
		 groupchat ->
			 case mod_eims_admin:acl(Cmd#cmd{args = [], context = Pkt}) of
				 #cmd{} ->
					 mod_eims_admin:exec_cmd(#cmd{name = ?file_rm, args = [B], context = From});
				 Err ->
					 ?DEBUG("ERROR: ~p", [Err])
			 end;
		 chat ->
			 mod_eims_admin:exec_cmd(#cmd{name = ?file_rm, args = [B], context = From});
		 _ -> ok
	 end || B <- Bodies].

-spec binary_to_number(binary()) -> float() | integer().
binary_to_number(B) ->
	try binary_to_float(B)
	catch
		error:badarg -> binary_to_integer(B)
	end.

-spec to_number(any()) -> float() | integer().
to_number(B) ->
	try binary_to_number(B)
	catch
		error:badarg -> {N, _} = string:to_float(B), N
	end.



string_to_lower(Binary) ->
	list_to_binary(string:lowercase(binary_to_list(Binary))).

%% encrypt data with key
pickle(Data) ->
	Message = term_to_binary(Data),
	Padding = size(Message) rem 16,
	Bits = (16 - Padding) * 8, Key = secret(), IV = crypto:strong_rand_bytes(16),
	Cipher = crypto:crypto_one_time(aes_128_cbc, Key, IV, <<Message/binary, 0:Bits>>, true),
	Signature = crypto:hash(sha256, <<Key/binary, Cipher/binary, IV/binary>>),
	base64:encode(<<IV/binary, Signature/binary, Cipher/binary>>).

depickle(PickledData) ->
	try Key = secret(),
	Decoded = base64:decode(iolist_to_binary(PickledData)),
	<<IV:16/binary, Signature:32/binary, Cipher/binary>> = Decoded,
	Signature = crypto:hash(sha256, <<Key/binary, Cipher/binary, IV/binary>>),
	binary_to_term(crypto:crypto_one_time(aes_128_cbc, Key, IV, Cipher, false), [safe])
	catch _:_ -> <<>> end.

secret() -> application:get_env(ejabberd, secret, <<"ThisIsClassified">>).

rename_map_key(OldKey, NewKey, #{} = Map) ->
	case Map of #{OldKey := V} -> maps:remove(OldKey, Map#{NewKey => V}); _ -> Map end.
rename_map_keys([], Map) -> Map;
rename_map_keys([{OldKey, NewKey} | T], Map) ->
	rename_map_keys(T, rename_map_key(OldKey, NewKey, Map)).
rename_map_keys(OldKeys, NewKeys, Map) ->
	rename_map_keys(lists:zip(OldKeys, NewKeys), Map).

%% TODO map_kv and map_map are unused
%%map_kv({K, V}, #{} = TMap) ->
%%	case maps:get(K, TMap, nil) of
%%		nil -> {K, V};
%%		{NK, Fun}  -> {NK, Fun(V)}
%%	end.
%%map_map(#{} = Map, #{} = TMap) ->
%%	maps:fold(
%%		fun(K, V, Acc) ->
%%			{NK, NV} = map_kv({K, V}, TMap),
%%			maps:put(NK, NV, Acc)
%%		end, #{}, Map).

%%find_tuple(Key, List, Idx) ->
%%	case lists:keyfind(Key, Idx, List) of
%%		false -> {error, not_found};
%%		Tuple -> {ok, Tuple}
%%	end.
dubl_values(K, Maps)->
	Values = [ V || #{K := V } <- Maps],
	Values--lists:uniq(Values).

-spec del_fields(Keys :: [term()], Map :: map()) -> map().
del_fields([], Map) ->
	Map;
del_fields([Key | Rest], Map) ->
	NewMap = maps:remove(Key, Map),
	del_fields(Rest, NewMap).

broadcast_from_bot(Msg) ->
	EIMSBot = jid:decode(Bot = bot_component()),
	[mod_muc:route(#message{type = groupchat, from = EIMSBot, to = jid:make(Name, Service),
		body = [#text{data = Msg}], sub_els = [#hint{type = 'no-store'}]}) || {Name, Service, _} <- mod_muc:get_online_rooms(?MUC_HOST),
		mod_muc_admin:get_room_affiliation(Name, Service, Bot) == admin].

find_html_el([], _Pred) -> false;
find_html_el([H | TEls], Pred) ->
	case find_html_el(H, Pred) of
		false -> find_html_el(TEls, Pred);
		HtmlEl -> HtmlEl
	end;
find_html_el(HtmlEl, Pred) ->
	case {Pred(HtmlEl), HtmlEl} of
		{false, #htmlDocument{content = Content}} -> find_html_el(Content, Pred);
		{false, #htmlElement{content = Content}} -> find_html_el(Content, Pred);
		{false, #htmlText{}} -> false;
		{true, _} -> HtmlEl
	end.

wait_for_stanza(Client) ->
	wait_for_stanza(Client, 5000).
wait_for_stanza(Client, Timeout) ->
	xmpp:decode(escalus:wait_for_stanza(Client, Timeout)).

wait_for_stanzas(Client, Count) ->
	wait_for_stanzas(Client, Count, 5000).
wait_for_stanzas(Client, Count, Timeout) ->
	[xmpp:decode(P) || P <- escalus:wait_for_stanzas(Client, Count, Timeout)].

send(Client, #xmlel{} = Pkt) ->
	escalus:send(Client, Pkt);
send(Client, Pkt) ->
	case xmpp:encode(Pkt) of
		#xmlel{} = Pkt2 -> send(Client, Pkt2);
		_ -> throw({error, invalid_decode})
	end.

route(#message{from = #jid{lserver = LServer} = From, meta = Meta} = Pkt) ->
	ejabberd_hooks:run_fold(user_send_packet, LServer, {Pkt2 = Pkt#message{meta = maps:merge(#{bot => true}, Meta)}, #{jid => From}}, []),
	ejabberd_router:route(Pkt2).

send_error(Pkt, access_denied) ->
	send_error(Pkt, "Access denied");
send_error(Pkt, Reason) when is_atom(Reason) ->
	send_error(Pkt, atom_to_binary(Reason));
send_error(#message{meta = Meta} = Pkt, Reason) ->
	send_edit(Pkt#message{meta = Meta#{bot => error}}, iolist_to_binary(io_lib:format("ERROR: ~s", [Reason]))).

fix_filter(Key) ->
	case maps:from_list(gen_mod:get_module_opt(global, mod_eims_admin, fix_filters)) of
		#{Key := Re} -> {ok, Re};
		#{} = Map -> maps:find(<<"default">>, Map)
	end.

fix_validate(Key, Value) -> %%TODO move to fix_transform module
	case fix_filter(Key) of
		error ->
			?dbg("can't find default filter", []), ok;
		{ok, Re} ->
			case re:run(Value, Re, [global, {capture, first, binary}]) of
				{match, [[Value] | _]} ->
					case banword_gen_server:member({en, binary_to_list(Value)}) of
						true -> {error, "\"" ++ binary_to_list(Key) ++ "\" has forbidden word"};
						_ -> ok
					end;
				Err ->
					?dbg("ERROR: ~p: ~s can't match ~s", [Err, Value, Re]),
					{error, "\"" ++ binary_to_list(Key) ++ "\" has forbidden symbol(s)"}
			end
	end.

get_json_payload(#xmlel{} = Pkt) ->
	get_json_payload(xmpp:decode(Pkt));
get_json_payload(#message{} = Pkt) ->
	case xmpp:get_subtag(Pkt, #message_payload{}) of
		#message_payload{json = #payload_json{data = Json}} ->
			case catch jiffy:decode(Json, [return_maps]) of
				#{} = Map -> Map;
				_ -> ?err("Invalid payload json"),
					{error, "Invalid payload json"}
			end;
		_ -> ?err("Message payload not found or corrupted"),
			{error, "Message payload not found or corrupted"}
	end.

get_json_from_entities(#xmlel{} = Pkt) ->
	get_json_from_entities(xmpp:decode(Pkt));
get_json_from_entities(#message{body = [#text{data = Text}]} = Pkt) ->
	#message_entities{items = Entities} = xmpp:get_subtag(Pkt, #message_entities{}),
	[jiffy:decode(binary:part(Text, Offset, Length), [return_maps]) || #message_entity{type = json, offset = Offset, length = Length} <- Entities].

encode_payload(Payload) ->
	#message_payload{json = #payload_json{data = jiffy:encode(Payload)}}.


%%holder_start() ->
%%	spawn(fun() ->
%%		receive
%%			{register, FuncRef} ->
%%				register(FuncRef),
%%				holder_start();
%%			{call, FuncRef} ->
%%							FuncRef()
%%				end,
%%				holder_start()
%%			end).
%%
%%%% Функция для регистрации функции
%%register_function(FuncRef) ->
%%	HolderPid = get_holder_pid(),
%%	HolderPid ! {register, FuncRef}.
%%
%%%% Функция для вызова функции
%%call_function(FuncRef) ->
%%	HolderPid = get_holder_pid(),
%%	HolderPid ! {call, FuncRef}.

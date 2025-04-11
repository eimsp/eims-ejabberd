-module(eims_db).
-compile(export_all).

%% Commands API
-export([]).

-include("logger.hrl").
-include_lib("xmpp/include/xmpp.hrl").
-include("mod_mam.hrl").
-include("eims.hrl").


-callback get_last_msgs(tuple(), integer(), binary() | #jid{} ) -> list() | {error, any()} | error.
-callback get_last_msgs(tuple(), integer()) -> list() | {error, any()} | error.
-callback get_mammsg_withrid_byid(tuple(), integer()) -> tuple() | {error, any()} | error.

start(Host) ->
	ejabberd_hooks:delete(store_mam_message, Host, mod_mam, store_mam_message, 100),
	ejabberd_hooks:add(store_mam_message, Host, ?MODULE, store_mam_message, 110).

stop(Host) ->
	ejabberd_hooks:delete(store_mam_message, Host, ?MODULE, store_mam_message, 110).

%% MAM hook
store_mam_message(Pkt = #message{meta = #{stanza_id := ID}}, U, S, Peer, Nick, Type, Dir) ->
	LServer = ejabberd_router:host_of_route(S),
	Mod = eims_db:get_db_mod(),
	Pkt2 = case xmpp:get_subtag(Pkt, #bot{}) of #bot{} = Bot -> xmpp:set_subtag(Pkt, Bot#bot{hash = <<>>}); _ -> Pkt end,
	Data = [Pkt2, xmpp:encode(Pkt2), LServer, US = {U, S}, Type, Peer, Nick, Dir, ID],
	case xmpp:get_subtag(Pkt2, #fasten_apply_to{}) of
		#fasten_apply_to{id = RetractId, sub_els = [#retract_id{}]} ->
			case select_by_query(Type, US, [{with_retract_id, RetractId}, {withtext, not_empty}]) of
				[#archive_msg{packet = RetractedPkt}] ->
					spawn(fun() -> eims:retract_upload(Pkt2, xmpp:decode(RetractedPkt)) end);
				_ ->
					?DEBUG("ERROR: mam message not found by ~s retract id in archive", [RetractId])
			end;
		_ -> ok
	end,
	Tags = [#replace{}, #fasten_apply_to{}, #receipt_response{}, #ps_event{}], %% key tags
	(eims:tag_decorator(Tags, Data, Mod, store))();
store_mam_message(Pkt, _U, _S, _Peer, _Nick, _Type, _Dir) ->
	Pkt.

%% MAM API

select_by_query(Type, {User, LServer} = US, Query) ->
	select_by_query(Type, {User, LServer} = US, Query, infinite).
select_by_query(Type, {User, LServer} = US, Query, Max) ->
	Host = ejabberd_router:host_of_route(LServer),
	JID = jid:make(User, LServer),
	{Msgs, _, _} = mod_mam:select(Host, JID, JID, Query, #rsm_set{max = Max}, Type, only_messages),
	[#archive_msg{id = Id, us = US, timestamp = Stamp,
		peer = case Type of groupchat -> From; _ -> To end,
		bare_peer = case Type of chat -> jid:remove_resource(To); groupchat -> jid:remove_resource(From) end,
		packet = xmpp:encode(Pkt),
		type = Type}
		|| {Id, _, #forwarded{delay = #delay{stamp = Stamp}, sub_els = [#message{from = From, to = To} = Pkt]}} <- Msgs].

select_by_id(Type, {_User, _LServer} = US, Id) when is_integer(Id) ->
	NowId = misc:usec_to_now(Id),
	select_by_query(Type, US, [{start, NowId}, {'end', NowId}]).
select_by_origin_id(Type, {_User, _LServer} = US, OId) ->
	select_by_query(Type, US, [{with_origin_id, OId}]).
select_by_retract_id(Type, {_User, _LServer} = US, RId) ->
	select_by_query(Type, US, [{with_retract_id, RId}]).

get_db_mod() ->
	list_to_atom("eims_" ++ atom_to_list(mod_mam_opt:db_type(global))).

remove_mam_msgs(Room, RoomHost, WithJid)->
	(get_db_mod()):remove_mam_msgs(Room, RoomHost, WithJid).

remove_mam_for_user(Room, RoomHost, Jid) ->
	(get_db_mod()):remove_mam_for_user(Room, RoomHost, Jid).

remove_mam_msg_by_ids(Room, RoomHost, Ids) ->
	(get_db_mod()):remove_mam_msg_by_ids(Room, RoomHost, Ids).

remove_mammsg_by_id(LServer,Id) ->
	(get_db_mod()):remove_mammsg_by_id(LServer,Id).

remove_from_archive_with_bare_peer(PeerJid) ->
	remove_from_archive_with_bare_peer(eims:host(), PeerJid).
remove_from_archive_with_bare_peer(LServer, PeerJid) ->
	(get_db_mod()):remove_from_archive_with_bare_peer(LServer, PeerJid).

%%remove_mammsg_by_rids(US, OriginIds)->
%%	(get_db_mod()):remove_mammsg_by_rids(US, OriginIds).
%%remove_mammsg_by_rids(Type, US, OriginIds)->
%%	(get_db_mod()):remove_mammsg_by_rids(Type, US, OriginIds).

get_mam_by_nick({Room, RoomHost}, Nick) ->
	(get_db_mod()):get_mam_by_nick({Room, RoomHost}, Nick).

get_last_msg(<<_/integer, _/binary>> = F) ->
	get_last_msg(jid:decode(F));
get_last_msg(#jid{luser = Room, lserver = RoomHost, resource = Nick} = _From) ->
	get_last_msg({Room, RoomHost}, Nick).
get_last_msg({Room, RoomHost} = US, NickORJid) ->
	case get_db_mod() of
		eims_sql ->
			case eims_sql:get_last_msgs(US, 1, NickORJid) of [LMsg] -> LMsg; E -> E end;
		_ ->
			eims_mnesia:get_last_msg({Room, RoomHost}, NickORJid)
	end.

get_mam_msg_by_id({User, Host}, Id) ->
	(get_db_mod()):get_mam_msg_by_id({User, Host}, Id).
get_mammsg_withrid_byid({User, Host}, Id) ->
	(get_db_mod()):get_mammsg_withrid_byid({User, Host}, Id).

edit_mam_msg_by_id({User, Host}, Id, Text) ->
	(get_db_mod()):edit_mam_msg_by_id({User, Host}, Id, Text).

edit_mammsg_by_oid(Type, {User, Host}, Ids, Text) ->
	(get_db_mod()):edit_mammsg_by_oid(Type, {User, Host}, Ids, Text).


upd_mammsg_by_id(Field, Oa,MamMsg) ->
	(get_db_mod()):upd_mammsg_by_id(Field, Oa, MamMsg).

get_last_msgs({Room, RoomHost}, Number) ->
	(get_db_mod()):get_last_msgs({Room, RoomHost}, Number).
get_last_msgs({Room, RoomHost}, Number, Nick) ->
	(get_db_mod()):get_last_msgs({Room, RoomHost}, Number, Nick);
get_last_msgs(Host, Number, Jid) ->
   (get_db_mod()):get_last_msgs(Host, Number, Jid).

read_archive(LUser, LServer) ->
	read_archive(LUser, LServer, {}).
read_archive(LUser, LServer, Jid) ->
	case get_db_mod() of
		eims_sql -> case eims_sql:read_archive(LUser, LServer, Jid) of [LMsg | _] = L -> L; E -> E end;
		_ -> mnesia:dirty_read(archive_msg, {LUser, LServer})
	end.

%% DB utils

upd_archive_by_originid() ->
	[LServer | _] = ejabberd_option:hosts(),
	Ids = lists:foldl(fun(MamMsg = #archive_msg{id = Id}, Os) ->
		case eims:get_msg_id(MamMsg) of
			{<<"a">>, E = {Id, Oa}} -> remove_mammsg_by_id(LServer, Id),
				case lists:keyfind(Oa, 2, Os) of
					{IdMamM, _} ->
						remove_mammsg_by_id(LServer, IdMamM),
						lists:keydelete(Oa, 2, Os);
					_ -> Os end;
			{<<"o">>, {Id, Oa} = E} -> upd_mammsg_by_id(origin_id, Oa, MamMsg),
				Os ++ [E];
			{<<"id">>, {Id, Oa} = E} -> upd_mammsg_by_id(origin_id, Oa, MamMsg),
				upd_mammsg_by_id(xml, [#xmlel{name = <<"active">>, attrs = [{<<"xmlns">>, ?NS_CHATSTATES}]},
					#xmlel{name = <<"origin-id">>, attrs = [{<<"xmlns">>, ?NS_SID_0}, {<<"id">>, Oa}]}], MamMsg),
				Os ++ [E];
			_ -> Os
		end end,
		[], eims_db:read_archive(<<"all">>, LServer, {})),
	ok.

all_records(Tab) ->
	lists:flatten([mnesia:dirty_read(Tab, Key) || Key = {U, _} <- mnesia:dirty_all_keys(Tab)]).

upd_tab1(Tab, Domain) ->
	[begin mnesia:dirty_delete(Tab, K), mnesia:dirty_write({Tab, {U, Domain}, Pass}) end || {Tab, {U, _} = K, Pass} <- all_records(Tab)].

upd_tab2(Tab, Domain) ->
	[begin mnesia:dirty_delete(Tab, K),  mnesia:dirty_write({Tab, {U, Domain}, {G, Domain}})  end || {Tab, {U, _ } = K, {G, _}} <- all_records(Tab)].
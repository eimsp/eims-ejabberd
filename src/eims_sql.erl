%%%-------------------------------------------------------------------
%%% @doc
%%% Module for SQL queries to table "archive"
%%% @end
%%% Created : 08. Dec 2021 11:10
%%%-------------------------------------------------------------------
-module(eims_sql).
-compile(export_all).

%% API
-export([]).

%%-export([init/2, remove_user/2, remove_room/3, delete_old_messages/3,
%%	extended_fields/0, store/8, write_prefs/4, get_prefs/2, select/7, export/1, remove_from_archive/3,
%%	is_empty_for_user/2, is_empty_for_room/3, select_with_mucsub/6]).

-include_lib("stdlib/include/ms_transform.hrl").
-include_lib("xmpp/include/xmpp.hrl").
-include("mod_mam.hrl").
-include("logger.hrl").
-include("ejabberd_sql_pt.hrl").
-include("mod_muc_room.hrl").
-include("eims.hrl").

%%%===================================================================
%%% API
%%%===================================================================

remove_mam_msgs(LUser, LServer, none) ->
	TS = <<"1">>,
	Jid = <<LUser/binary, "@", LServer/binary>>,
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer),
		?SQL("delete from archive where username=%(Jid)s and %(LServer)H and timestamp > %(TS)d")) of
		{error, Reason} -> {error, Reason};
		_ -> ok
	end;
remove_mam_msgs(LUser, LServer, WithJid) ->
	Peer = jid:encode(jid:remove_resource(WithJid)),
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer),
		?SQL("delete from archive here username=%(LUser)s and %(LServer)H and bare_peer=%(Peer)s")) of
		{error, Reason} -> {error, Reason};
		_ -> ok
	end.

remove_from_archive_with_bare_peer(LServer, #jid{} = PeerJid) ->
	remove_from_archive_with_bare_peer(LServer, jid:encode(jid:remove_resource(PeerJid)));
remove_from_archive_with_bare_peer(LServer, PeerJid) ->
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer),
		?SQL("delete from archive where %(LServer)H and bare_peer=%(PeerJid)s")) of
		{error, Reason} -> ?dbg("ERROR : ~p", [Reason]), {error, Reason};
		_ -> ok
	end.

select_private_messages_from_archive(#jid{luser = User, lserver = Host}, #jid{} = Peer) ->
	lists:flatten(
		[case xmpp:get_subtag(DecPkt = xmpp:decode(Pkt), #origin_id{}) of
			 #origin_id{id = _OriginId} ->
				 DecPkt;
			 _ -> []
		 end || #archive_msg{packet = Pkt} <- eims_db:select_by_query(chat, {User, Host}, [{with, Peer}])]).

select_messages_like_peer(PeerMask) ->
	select_messages_like_peer(?HOST, PeerMask).
select_messages_like_peer(LServer, PeerMask) ->
	case ejabberd_sql:sql_query(LServer,
		?SQL("select @(xml)s "
			 "from archive where %(LServer)H and peer like %(PeerMask)s %ESCAPE order by id")) of
		{selected, Msgs} -> decode_msgs(Msgs);
		{error, Reason} -> ?dbg("ERROR : ~p", [Reason]), {error, Reason}
	end.

remove_messages_like_peer(PeerMask) ->
	remove_messages_like_peer(?HOST, PeerMask).
remove_messages_like_peer(LServer, PeerMask) ->
	case ejabberd_sql:sql_query(LServer,
		?SQL("delete from archive where %(LServer)H and peer like %(PeerMask)s")) of
		{error, Reason} -> ?err("~p", [Reason]), {error, Reason};
		_ -> ok
	end.

select_messages_like_bare_peer(PeerMask) ->
	select_messages_like_bare_peer(?HOST, PeerMask).
select_messages_like_bare_peer(LServer, PeerMask) ->
	case ejabberd_sql:sql_query(LServer,
		?SQL("select @(xml)s "
			 "from archive where %(LServer)H and bare_peer like %(PeerMask)s %ESCAPE order by id")) of
		{selected, Msgs} -> decode_msgs(Msgs);
		{error, Reason} -> ?dbg("ERROR : ~p", [Reason]), {error, Reason}
	end.

select_messages_by_peer_mask(LServer, #jid{} = BarePeerJID) ->
	BarePeerJid = jid:encode(jid:remove_resource(BarePeerJID)),
	PeerMask = <<BarePeerJid/binary, "/%">>,
	select_messages_like_peer(LServer, PeerMask).
select_messages_by_peer_mask(#jid{} = PeerJID) ->
	select_messages_by_peer_mask(?HOST, #jid{} = PeerJID).

remove_mam_for_user(LUser, LServer, #jid{} = PJid) ->
	Jid = <<LUser/binary, "@", LServer/binary>>,
	PeerJid = jid:encode(PJid),
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer),
		?SQL("delete from archive where username=%(Jid)s and %(LServer)H and bare_peer=%(PeerJid)s")) of
		{error, Reason} -> ?dbg("ERROR : ~p", [Reason]), {error, Reason};
		_ -> ok
	end;
remove_mam_for_user(LUser, LServer, Nick) ->
	Jid = <<LUser/binary, "@", LServer/binary>>,
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer),
		?SQL("delete from archive where username=%(Jid)s and %(LServer)H and nick=%(Nick)s")) of
		{error, Reason} -> ?dbg("ERROR : ~p", [Reason]), {error, Reason};
		_ -> ok
	end.


remove_mammsg_by_id(LServer, Id) ->
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer),
		?SQL("delete from archive where timestamp=%(Id)d and %(LServer)H")) of
		{error, Reason} -> ?dbg("ERROR : ~p", [Reason]), {error, Reason};
		_ -> ok
	end.
remove_mam_msg_by_ids(LUser, LServer, [Id]) when is_binary(Id) or is_integer(Id) ->
	Jid = case LUser of {User, <<>>} -> User; _ -> <<LUser/binary, "@", LServer/binary>> end,
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer),
		?SQL("delete from archive where username=%(Jid)s and %(LServer)H and timestamp=%(Id)d")) of
		{error, Reason} -> ?dbg("ERROR : ~p", [Reason]), {error, Reason};
		_ -> ok
	end;
remove_mam_msg_by_ids(LUser, LServer, [Id | _] = Ids) when is_binary(Id) or is_integer(Id) ->
	I = str:join([ejabberd_sql:to_string_literal(pgsql, X) || X <- Ids], <<",">>),
	Jid = <<LUser/binary, "@", LServer/binary>>,
	%ct:pal("remove_mam_msg_by_ids : ~p,~p,~p ", [LUser,  LServer, I]),
	case
		ejabberd_sql:sql_query_t([<<"delete from archive where timestamp in (">>,
			I, <<") and username=%(Jid)s and %(LServer)H;">>]) of
		{updated, N} -> ?dbg("remove_mam_msg_by_ids : ~p", [N]), ok;
		E -> ?dbg("ERROR remove_mam_msg_by_ids : ~p", [E]), {error, xmpp:err_item_not_found()}
	end;
remove_mam_msg_by_ids(LUser, LServer, Ids) ->
	{error, <<"Bad ID">>}.

%%remove_mammsg_by_rids({LUser, LServer, chat}, [RId]) when is_binary(RId) ->
%%  case get_msgs(chat, {LUser, LServer}, RId) of
%%    {_, {error, E}} -> ?dbg("ERROR : ~p", [E]), {error, not_found};
%%    {_, []} -> {error, not_found};
%%    {Fun, Msgs} ->
%%      case lists:flatten([case xmpp:decode(Msg) of
%%                           #message{body = []} -> ok = remove_mam_msg_by_ids({LUser, <<>>}, LServer, [DelId]), [];
%%                           #message{} = NM -> {Fun(chat, {LUser, LServer}, [RId]), NM} end
%%                           || #archive_msg{id = DelId, packet = Msg} = ArcMsg <- Msgs]) of
%%      [{ Result, #message{id = MId, sub_els = SubEls0} = NMsg} = Pkt|_ ] ->
%%  %if RetractId==RId  -> ok ;  true -> Fun(chat, {LUser, LServer}, [RetractId]) end,
%%        case xmpp:get_subtag(Pkt, #fasten_apply_to{}) of
%%          #fasten_apply_to{id = StoreId} -> {updated, _} = remove_mammsg_by_rids(chat, {LUser, LServer}, [StoreId]);
%%                                  _ -> {updated, _} = Result
%%        end;
%%   %                                      remove_mammsg_by_rids(chat, {LUser, LServer}, [RId]);
%%       _ -> {error, not_found}
%%      end
%%   end,
%%  ok;
%%remove_mammsg_by_rids({LUser, LServer, groupchat}, [RId]) when is_binary(RId) ->
%%	case remove_mammsg_by_rids(groupchat, {LUser, LServer}, [RId]) of
%%		{updated, N} when N > 0 -> ok;
%%		_ -> {updated, _} = remove_mammsg_by_oids(groupchat, {LUser, LServer}, [RId]), ok
%%	end;
%%remove_mammsg_by_rids(_US, _Ids) ->
%%	{error, <<"Bad ID">>}.
%%
%%remove_mammsg_by_rids(Type, {LUser, LServer}, [RId]) when is_binary(RId) ->
%%	Jid = case Type of chat -> LUser; _ -> <<LUser/binary, "@", LServer/binary>> end,
%%	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL("delete from archive where username=%(Jid)s and %(LServer)H and retract_id=%(RId)d")) of
%%		{error, Reason} -> ?dbg("ERROR : ~p", [Reason]), {error, Reason};
%%		R -> R
%%	end;
%%remove_mammsg_by_rids(_Type, _US, _Ids) ->
%%	{error, <<"Bad ID">>}.
%%remove_mammsg_by_oids(Type, {LUser, LServer}, [RId]) when is_binary(RId) ->
%%	Jid = case Type of chat -> LUser; _ -> <<LUser/binary, "@", LServer/binary>> end,
%%	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL("delete from archive where username=%(Jid)s and %(LServer)H and origin_id=%(RId)d")) of
%%		{error, Reason} -> ?dbg("ERROR : ~p", [Reason]), {error, Reason};
%%		R -> R
%%	end;
%%remove_mammsg_by_oids(_Type, _US, _Ids) ->
%%	{error, <<"Bad ID">>}.

read_archive(<<"all">>, LServer, {}) ->
	%LServer = <<"localhost">>,
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
		"select @(username)s, @(id)d, @(timestamp)d, @(peer)s, @(bare_peer)s, @(xml)s, @(nick)s, @(kind)s from archive where %(LServer)H order by id")) of
		%case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL("select * from archive where username=%(LUser)s and %(LServer)H")) of
		{selected, []} -> [];
		{selected, L} -> tuple_to_msg(L);
		_ -> error
	end;
read_archive(<<"all">>, LServer, {Kind}) ->
	%LServer = <<"localhost">>,
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
		"select @(username)s, @(id)d, @(timestamp)d, @(peer)s, @(bare_peer)s, @(xml)s, @(nick)s, @(kind)s from archive where kind=%(Kind)s and %(LServer)H order by id")) of
		%case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL("select * from archive where username=%(LUser)s and %(LServer)H")) of
		{selected, []} -> [];
		{selected, L} -> tuple_to_msg(L);
		_ -> error
	end;
read_archive(LUser, LServer, {}) ->
	Jid = <<LUser/binary, "@", LServer/binary>>,
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
		"select @(username)s, @(id)d, @(timestamp)d, @(peer)s, @(bare_peer)s, @(xml)s, @(nick)s, @(kind)s from archive where username=%(Jid)s and %(LServer)H order by id")) of
		%case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL("select * from archive where username=%(LUser)s and %(LServer)H")) of
		{selected, []} -> [];
		{selected, L} -> tuple_to_msg(L);
		_ -> error
	end;
read_archive(LUser, LServer, #jid{} = PJid) ->
	Jid = <<LUser/binary, "@", LServer/binary>>,
	PeerJid = jid:encode(PJid),
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
		"select @(username)s, @(id)d, @(timestamp)d, @(peer)s, @(bare_peer)s, @(xml)s, @(nick)s, @(kind)s from archive where bare_peer=%(PeerJid)s and username=%(Jid)s and %(LServer)H order by id")) of
		%case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL("select * from archive where username=%(LUser)s and %(LServer)H")) of
		{selected, []} -> [];
		{selected, L} -> tuple_to_msg(L);
		_ -> error
	end.

%%get_msgs(Type, {LUser, LServer}, RId) when is_binary(RId) ->
%%	case get_mammsg_by_rid(Type, {LUser, LServer}, RId) of
%%		[#archive_msg{} | _] = Msgs -> {fun remove_mammsg_by_rids/3, Msgs};
%%		_ -> {fun remove_mammsg_by_oids/3, get_mammsg_by_oid(Type, {LUser, LServer}, RId)}
%%	end.

get_last_msgs({LUser, LServer}, Number) ->
	Jid = <<LUser/binary, "@", LServer/binary>>,
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
		"select @(username)s, @(id)d, @(timestamp)d, @(peer)s, @(bare_peer)s, @(xml)s, @(nick)s, @(kind)s "
		"from archive where username=%(Jid)s and %(LServer)H order by id desc limit %(Number)s")) of
		{selected, []} -> [];
		{selected, L} -> tuple_to_msg(L);
		%?dbg("LAST_MSG FOR ALL: ~p", [NL]), NL;
		E -> {error, E}
	end.

get_last_msgs({LUser, LHost}, Number, #jid{lserver = LServer} = PJid) ->
	case ejabberd_router:host_of_route(hd(ejabberd_option:hosts())) of LServer->LServer,
		SUser = jid:encode({LUser, LHost, <<>>}),
		PeerJid = jid:encode(jid:remove_resource(PJid)),
		case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
		"select @(username)s, @(id)d, @(timestamp)d, @(peer)s, @(bare_peer)s, @(xml)s, @(nick)s, @(kind)s "
		"from archive where username=%(SUser)s and %(LServer)H and bare_peer=%(PeerJid)s order by id desc limit %(Number)s")) of
		%case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL("select * from archive where username=%(LUser)s and %(LServer)H")) of
			{selected, []} -> {error, not_found};
			{selected, L} -> NL = tuple_to_msg(L),
				?dbg("LAST_MSG : ~p", [NL]), NL;
			E -> {error, E}
		end;
	 	E -> {error, E}
	end;
get_last_msgs(LServer, Number, #jid{} = PJid) ->
	case ejabberd_router:host_of_route(hd(ejabberd_option:hosts())) of LServer -> LServer,
		PeerJid = jid:encode(jid:remove_resource(PJid)),
		case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
			"select @(username)s, @(id)d, @(timestamp)d, @(peer)s, @(bare_peer)s, @(xml)s, @(nick)s, @(kind)s "
			"from archive where %(LServer)H and bare_peer=%(PeerJid)s order by id desc limit %(Number)s")) of
			%case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL("select * from archive where username=%(LUser)s and %(LServer)H")) of
			{selected, []} -> [];
			{selected, L} -> NL = tuple_to_msg(L),
				?dbg("LAST_MSG : ~p", [NL]), NL;
			E -> {error, E}
		end;
		E -> {error, E}
	end;
get_last_msgs({LUser, LServer} = US, Number, PeerNick) ->
	Jid = <<LUser/binary, "@", LServer/binary>>,
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
		"select @(username)s, @(id)d, @(timestamp)d, @(peer)s, @(bare_peer)s, @(xml)s, @(nick)s, @(kind)s "
		"from archive where username=%(Jid)s and %(LServer)H and nick=%(PeerNick)s order by id desc limit %(Number)s")) of
		%case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL("select * from archive where username=%(LUser)s and %(LServer)H")) of
		{selected, []} -> {error, not_found};
		{selected, L} ->
			NL = tuple_to_msg(L),
			?dbg("LAST_MSG : ~p", [NL]), NL;
		_ -> error
	end.


get_mam_msg_by_id({_User, LServer} = US, Id) when is_binary(Id) or is_integer(Id) ->
	Jid = <<_User/binary, "@", LServer/binary>>,
	%erlang:display({"get_mam_msg_by_ids : ~p, ~p", [US,Id]}),
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
		"select @(username)s, @(id)d, @(timestamp)d, @(peer)s, @(bare_peer)s, @(xml)s, @(nick)s, @(kind)s "
		"from archive where username=%(Jid)s and %(LServer)H and timestamp=%(Id)d order by id desc limit 1")) of
		%case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL("select * from archive where username=%(LUser)s and %(LServer)H")) of
		{selected, []} -> {error, not_found};
		{selected, [Msg] = L} -> [NL] = tuple_to_msg(L), NL;
		E -> {error, E}
	end;
get_mam_msg_by_id(US, Id) ->
  {error,<<"Bad ID">>}.


get_mammsg_withrid_byid({_User, LServer}=US, Id) when is_binary(Id) or is_integer(Id)->
  Jid = <<_User/binary,"@",LServer/binary>>,
  %erlang:display({"get_mam_msg_by_ids : ~p, ~p", [US,Id]}),
  case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
    "select @(retract_id)s, @(username)s, @(id)d, @(timestamp)d, @(peer)s, @(bare_peer)s, @(xml)s, @(nick)s, @(kind)s "
    "from archive where username=%(Jid)s and %(LServer)H and timestamp=%(Id)d order by id desc limit 1")) of
    %case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL("select * from archive where username=%(LUser)s and %(LServer)H")) of
    {selected, []} ->  {error, not_found};
    {selected, [MsgRid]} -> [Rid|LMsg] = erlang:tuple_to_list(MsgRid),
                            Msg = erlang:list_to_tuple(LMsg), [NL] = tuple_to_msg([Msg]), {Rid, NL};
    E -> {error, E}
  end.

select_all_by_origin_id(OriginId) ->
	LServer = eims:host(),
	case ejabberd_sql:sql_query(LServer, ?SQL(
		"select  @(xml)s "
		"from archive where %(LServer)H and origin_id=%(OriginId)d order by id")) of
		{selected, []} -> {error, not_found};
		{selected, [_ | _] = Msgs} -> decode_msgs(Msgs);
		E -> {error, E}
	end.

select_by_origin_id(RetractId) ->
	case select_all_by_origin_id(RetractId) of %% TODO in future parse only first element
		[_ | _] = Msgs -> lists:last(Msgs);
		Res -> Res
	end.


select_all_by_retract_id(RetractId) ->
	LServer = eims:host(),
	case ejabberd_sql:sql_query(LServer, ?SQL(
		"select  @(xml)s "
		"from archive where %(LServer)H and retract_id=%(RetractId)d order by id")) of
		{selected, []} -> {error, not_found};
		{selected, [_ | _] = Msgs} -> decode_msgs(Msgs);
		E -> {error, E}
	end.

select_by_retract_id(RetractId) ->
	case select_all_by_retract_id(RetractId) of %% TODO in future parse only first element
		[_ | _] = Msgs -> lists:last(Msgs);
		Res -> Res
	end.

select_username_by_retract_id(RetractId) ->
	LServer = eims:host(),
	case ejabberd_sql:sql_query(LServer, ?SQL(
		"select  @(username)s "
		"from archive where %(LServer)H and retract_id=%(RetractId)d order by id")) of
		{selected, []} -> {error, not_found};
		{selected, [{Username} | _]} -> Username;
		E -> {error, E}
	end.

remove_by_retract_id(RetractId) ->
	LServer = eims:host(),
	case ejabberd_sql:sql_query(LServer, ?SQL(
		"delete from archive where %(LServer)H and retract_id=%(RetractId)s")) of
		{updated, 0} ->
			{error, not_found};
		{updated, N} -> ok;
		E -> ?dbg("ERROR remove_by_retract_id : ~p", [E]),
			{error, E}
	end.

get_rid(Type, {User, LServer}, OId) when is_binary(OId) ->
	Jid = case Type of groupchat -> <<User/binary, "@", LServer/binary>>; chat -> User end,
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
		"select  @(retract_id)s "
		"from archive where username=%(Jid)s and %(LServer)H and origin_id=%(OId)d order by id")) of
		{selected, []} -> {error, not_found};
		{selected, [{OriginId} | _]} -> OriginId;
		E -> {error, E}
	end;
get_rid(_Type, _US, Id) ->
	{error, Id}.

get_oid(Type, {User, LServer}, RId) when is_binary(RId) ->
	Jid = case Type of groupchat -> <<User/binary, "@", LServer/binary>>; chat -> User end,
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
		"select  @(origin_id)s "
		"from archive where username=%(Jid)s and %(LServer)H and retract_id=%(RId)d order by id")) of
		{selected, []} -> {error, not_found};
		{selected, [{OriginId} | _]} -> OriginId;
		E -> {error, E}
	end;
get_oid(_Type, _US, Id) ->
	{error, Id}.



edit_mam_msg_by_id({_User, LServer} = US, Id, Txt) when is_binary(Id) or is_integer(Id) ->
	Jid = <<_User/binary, "@", LServer/binary>>,
	case get_mam_msg_by_id({_User, LServer}, Id) of
		#archive_msg{packet = Msg1} = AMsg -> Msg2 = #message{} = xmpp:decode(Msg1),
			Msg3 = xmpp:encode(Msg2#message{body = [#text{data = Txt}]}),
			XML = fxml:element_to_binary(Msg3),
			case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
				"update archive set txt = %(Txt)s, xml = %(XML)s where username=%(Jid)s and %(LServer)H and timestamp=%(Id)d")) of
%                " returning @(username)s, @(id)d, @(timestamp)d, @(peer)s, @(bare_peer)s, @(xml)s, @(nick)s, @(kind)s")) of
%                {updated, undefined} ->  ct:pal("Undefined : ~p", [{error, undefined}]),{error, undefined};
				{updated, _} -> AMsg#archive_msg{packet = Msg3};
				E -> ?dbg("ERROR : ~p", [E]), {error, E}
			end;
		E -> {error, E}
	end;
edit_mam_msg_by_id(US, Id, Txt) ->
	{error, <<"Bad ID">>}.

%%edit_mammsg_by_oid(Type, {User, LServer} = US, {OId, NewOId, MsgId}, Txt) when is_binary(OId) ->
%%	Jid = case Type of chat -> User; _ -> <<User/binary, "@", LServer/binary>> end,
%%	case get_mammsg_by_oid(Type, {User, LServer}, OId) of
%%		[#archive_msg{} | _] = Msgs -> [{#archive_msg{id = Id} = AMsg, #message{id = MId, sub_els = SubEls0} = NMsg}] =
%%			lists:flatten(
%%				[case xmpp:decode(Msg) of
%%					 #message{body = []} -> ok = remove_mam_msg_by_ids({User, <<>>}, LServer, [DelId]), [];
%%					 #message{} = NM -> {ArcMsg, NM}
%%				 end || #archive_msg{id = DelId, packet = Msg} = ArcMsg <- Msgs]),
%%			case lists:keyfind(apply_to, 1, SubEls0) of
%%%                                           {origin_id, StoreId} when StoreId =/= OId, Type == chat ->
%%				#fasten_apply_to{id = StoreId} when Type == chat ->
%%					remove_mammsg_by_rids(chat, {User, LServer}, [StoreId]),
%%					SubEls1 = lists:keystore(apply_to, 1, SubEls0, #fasten_apply_to{id = MsgId});
%%				false when Type == chat -> SubEls1 = lists:keystore(apply_to, 1, SubEls0, #fasten_apply_to{id = MsgId});
%%				_ -> SubEls1 = SubEls0
%%			end,
%%			SubEls = SubEls1, %lists:keyreplace(origin_id, 1, SubEls1, {origin_id, NewOId}),
%%			NMsg1 = NMsg#message{body = [#text{data = Txt}], sub_els = SubEls},
%%			NewMsg = xmpp:encode(NMsg1),
%%			%erlang:display({"EDIT :", [MsgId, NewMsg]}),
%%			XML = fxml:element_to_binary(NewMsg),
%%			case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
%%				"update archive set txt = %(Txt)s, xml = %(XML)s, retract_id=%(NewOId)s where username=%(Jid)s and %(LServer)H and timestamp=%(Id)d")) of
%%				{updated, _} ->  %case Type of chat when MId == OId -> remove_mammsg_by_rids(chat, {User, LServer}, [MId]); _ -> ok end ,
%%					AMsg#archive_msg{packet = NewMsg};
%%				E -> ?dbg("ERROR : ~p", [E]), {error, E}
%%			end;
%%		E -> {error, E}
%%	end;
%%edit_mammsg_by_oid(T_ype, _F, _US, _Txt) ->
%%	{error, <<"Bad ID">>}.

get_rid_by_oid(OriginId, LServer) ->
	Text = <<>>,
	case ejabberd_sql:sql_query(LServer, ?SQL(
		"select @(retract_id)s "
		"from archive where txt!=%(Text)s and %(LServer)H and origin_id=%(OriginId)d order by id")) of
		{selected, []} -> {error, not_found};
		{selected, [{H} | _]} -> H;
		E -> {error, E}
	end.

get_oid_by_rid(RetractId, LServer) ->
	Text = <<>>,
	case ejabberd_sql:sql_query(LServer, ?SQL(
		"select @(origin_id)s "
		"from archive where txt!=%(Text)s and %(LServer)H and retract_id=%(RetractId)d order by id")) of
		{selected, []} -> {error, not_found};
		{selected, [{H} | _]} -> H;
		E -> {error, E}
	end.

%% Search by  retract_id

get_msg_like_retract_id(Mask, LServer) ->
	Text = <<>>,
	case ejabberd_sql:sql_query(LServer, ?SQL(
		"select @(xml)s "
		"from archive where txt!=%(Text)s and %(LServer)H and retract_id like %(Mask)s %ESCAPE order by id")) of
		{selected, []} -> [];
		{selected, [_ | _] = Msgs} -> decode_msgs(Msgs);
		E -> {error, E}
	end.

get_msg_like_retract_id(Mask, {bare, #jid{} = Peer}, LServer) ->
	get_msg_like_retract_id(Mask, {bare, jid:encode(jid:remove_resource(Peer))}, LServer);
get_msg_like_retract_id(Mask, {bare, BarePeer}, LServer) ->
	Text = <<>>,
	case ejabberd_sql:sql_query(LServer, ?SQL(
		"select @(xml)s "
		"from archive where txt!=%(Text)s and %(LServer)H and bare_peer=%(BarePeer)s and retract_id like %(Mask)s %ESCAPE order by id")) of
		{selected, []} -> [];
		{selected, [_ | _] = Msgs} -> decode_msgs(Msgs);
		E -> {error, E}
	end;
get_msg_like_retract_id(Mask, #jid{} = Peer, LServer) ->
	get_msg_like_retract_id(Mask, jid:encode(Peer), LServer);
get_msg_like_retract_id(Mask, Peer, LServer) ->
	Text = <<>>,
	case ejabberd_sql:sql_query(LServer, ?SQL(
		"select @(xml)s "
		"from archive where txt!=%(Text)s and %(LServer)H and peer=%(Peer)s and retract_id like %(Mask)s %ESCAPE order by id")) of
		{selected, []} -> [];
		{selected, [_ | _] = Msgs} -> decode_msgs(Msgs);
		E -> {error, E}
	end.

get_msg_like_retract_id(Mask, #jid{} = Peer, User, LServer) ->
	get_msg_like_retract_id(Mask, jid:encode(Peer), User, LServer);
get_msg_like_retract_id(Mask, Peer, User, LServer) ->
	Text = <<>>,
	case ejabberd_sql:sql_query(LServer, ?SQL(
		"select @(xml)s "
		"from archive where txt!=%(Text)s and %(LServer)H and peer=%(Peer)s and username=%(User)s and retract_id like %(Mask)s %ESCAPE order by id")) of
		{selected, []} -> [];
		{selected, [_ | _] = Msgs} -> decode_msgs(Msgs);
		E -> {error, E}
	end.

%% Search by origin_id


get_msg_like_origin_id(Mask, LServer) ->
	Text = <<>>,
	case ejabberd_sql:sql_query(LServer, ?SQL(
		"select @(xml)s "
		"from archive where txt!=%(Text)s and %(LServer)H and origin_id like %(Mask)s %ESCAPE order by id")) of
		{selected, []} -> [];
		{selected, [_ | _] = Msgs} -> decode_msgs(Msgs);
		E -> {error, E}
	end.

get_msg_like_origin_id(Mask, {bare, #jid{} = Peer}, LServer) ->
	get_msg_like_origin_id(Mask, {bare, jid:encode(jid:remove_resource(Peer))}, LServer);
get_msg_like_origin_id(Mask, {bare, Peer}, LServer) ->
	Text = <<>>,
	case ejabberd_sql:sql_query(LServer, ?SQL(
		"select @(xml)s "
		"from archive where txt!=%(Text)s and %(LServer)H and peer=%(Peer)s and origin_id like %(Mask)s %ESCAPE order by id")) of
		{selected, []} -> [];
		{selected, [_ | _] = Msgs} -> decode_msgs(Msgs);
		E -> {error, E}
	end;
get_msg_like_origin_id(Mask, #jid{} = Peer, LServer) ->
	get_msg_like_origin_id(Mask, jid:encode(Peer), LServer);
get_msg_like_origin_id(Mask, Peer, LServer) ->
	Text = <<>>,
	case ejabberd_sql:sql_query(LServer, ?SQL(
		"select @(xml)s "
		"from archive where txt!=%(Text)s and %(LServer)H and peer=%(Peer)s and origin_id like %(Mask)s %ESCAPE order by id")) of
		{selected, []} -> [];
		{selected, [_ | _] = Msgs} -> decode_msgs(Msgs);
		E -> {error, E}
	end.

get_msg_like_origin_id(Mask, #jid{} = Peer, User, LServer) ->
	get_msg_like_origin_id(Mask, jid:encode(Peer), User, LServer);
get_msg_like_origin_id(Mask, Peer, User, LServer) ->
	Text = <<>>,
	case ejabberd_sql:sql_query(LServer, ?SQL(
		"select @(xml)s "
		"from archive where txt!=%(Text)s and %(LServer)H and peer=%(Peer)s and username=%(User)s and origin_id like %(Mask)s %ESCAPE order by id")) of
		{selected, []} -> [];
		{selected, [_ | _] = Msgs} -> decode_msgs(Msgs);
		E -> {error, E}
	end.



get_message_by_xml_mask(Mask) ->
	LServer = ?HOST,
	case ejabberd_sql:sql_query(LServer, ?SQL(
		"select @(xml)s "
		"from archive where %(LServer)H and xml like %(Mask)s %ESCAPE order by id")) of
		{selected, []} -> [];
		{selected, [_ | _] = Msgs} -> decode_msgs(Msgs);
		E -> {error, E}
	end.

get_bare_msg_like_retract_id(Mask, #jid{} = BarePeer, User, LServer) ->
	get_bare_msg_like_retract_id(Mask, jid:encode(jid:remove_resource(BarePeer)), User, LServer);
get_bare_msg_like_retract_id(Mask, BarePeer, User, LServer) ->
	Text = <<>>,
	case ejabberd_sql:sql_query(LServer, ?SQL(
		"select @(xml)s "
		"from archive where txt!=%(Text)s and %(LServer)H and bare_peer=%(BarePeer)s and username=%(User)s and retract_id like %(Mask)s %ESCAPE order by id")) of
		{selected, []} -> [];
		{selected, [_ | _] = Msgs} -> decode_msgs(Msgs);
		E -> {error, E}
	end.

upd_mammsg_by_id(xml, SE, #archive_msg{us = {U, LServer}, id = Id, packet = Msg1} = AMsg) when is_binary(Id) or is_integer(Id) ->
	Msg2 = #message{sub_els = SubEls0} = xmpp:decode(Msg1),
	SubEls = SE ++ SubEls0,
	Msg3 = xmpp:encode(Msg2#message{sub_els = SubEls}),
	XML = fxml:element_to_binary(Msg3),
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
		"update archive set xml = %(XML)s where %(LServer)H and timestamp=%(Id)d")) of
		{updated, _} -> AMsg#archive_msg{packet = Msg3};
		E -> ?dbg("ERROR : ~p", [E]), {error, E}
	end;
upd_mammsg_by_id(origin_id, Txt, #archive_msg{us = {U, LServer}, id = Id} = AMsg) when is_binary(Id) or is_integer(Id) ->
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
		"update archive set origin_id = %(Txt)s where %(LServer)H and timestamp=%(Id)d")) of
		{updated, _} -> AMsg;
		E -> ?dbg("ERROR : ~p", [E]), {error, E}
	end;
upd_mammsg_by_id(_F, _US, _MamMsg) ->
	{error, <<"Bad ID">>}.

store([DecodedPkt | TailData]) ->
	Ids =
		case xmpp:get_subtag(DecodedPkt, #origin_id{}) of
			#origin_id{id = OriginId} ->
				[OriginId, OriginId];
			_ ->
				?DEBUG("WARNING: origin_id not found in ~p", [DecodedPkt]),
				[<<>>, <<>>]
		end,
	erlang:apply(?MODULE, store, TailData ++ Ids).
store(#ps_event{}, [DecodedPkt | [Pkt, LServer, {User, LHost}, chat | _] = TailData]) ->
	case misc:unwrap_mucsub_message(DecodedPkt) of
		#message{} = WrappedPkt ->
			case [xmpp:get_subtag(WrappedPkt, Tag) || Tag <- [#fasten_apply_to{}, #replace{}]] of
				[#fasten_apply_to{sub_els = [#retract_id{}]}, _] ->
					DecodedPkt;
				[_, #replace{}] ->
					#origin_id{id = LastOriginId} = xmpp:get_subtag(WrappedPkt, #origin_id{}),
					case get_oid_by_rid(LastOriginId, LServer) of
						{error, not_found} ->
							?DEBUG("ERROR: can't find origin id by retract id for mucpubsub: ~p", [DecodedPkt]),
							erlang:apply(?MODULE, store, TailData ++ [LastOriginId, LastOriginId]);
						LastOriginId ->
							erlang:apply(?MODULE, store, TailData ++ [LastOriginId, LastOriginId]);
						OriginId -> %% update replaced pubsub message
							Xml = fxml:element_to_binary(Pkt),
							T = <<>>,
							case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
								"update archive set xml = %(Xml)s, retract_id = %(LastOriginId)s"
								" where %(LServer)H and username = %(User)s and origin_id = %(OriginId)s and txt = %(T)s")) of
								{updated, _} -> DecodedPkt;
								Err ->
									?DEBUG("ERROR: ~p", [Err]),
									DecodedPkt
							end
					end;
				_ ->
					#origin_id{id = OriginId} = xmpp:get_subtag(WrappedPkt, #origin_id{}),
					erlang:apply(?MODULE, store, TailData ++ [OriginId, OriginId])
			end;
		_ ->
			?DEBUG("WARNING: origin_id not found in ~p", [DecodedPkt]),
			erlang:apply(?MODULE, store, TailData ++ [<<>>, <<>>])
	end;
store(#replace{id = EditedOriginId}, [DecodedPkt = #message{body = [#text{data = Body}]} | [_Pkt, LServer, {LUser, LHost}, Type | _] = TailData]) ->
	SUser = case Type of chat -> LUser; groupchat -> jid:encode({LUser, LHost, <<>>}) end,
	#origin_id{id = RetractId} = xmpp:get_subtag(DecodedPkt, #origin_id{}),
	T = <<>>,
	case get_rid_by_oid(EditedOriginId, LServer) of
		{error, _} ->
			erlang:apply(?MODULE, store, TailData ++ [RetractId, RetractId]);
		_RId ->
			Xml = fxml:element_to_binary(xmpp:encode(DecodedPkt#message{id = EditedOriginId})),
			case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), ?SQL(
				"update archive set xml = %(Xml)s, txt = %(Body)s, retract_id = %(RetractId)s"
				" where %(LServer)H and username = %(SUser)s and origin_id = %(EditedOriginId)s and txt != %(T)s")) of
				{updated, _} when Type == chat ->
					case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), %% remove receipt_response or pubsub with empty body %% TODO update in future for pubsub
						?SQL("delete from archive where %(LServer)H and origin_id = %(EditedOriginId)s and txt = %(T)s")) of
						{error, Reason} ->
							?dbg("ERROR: ~p", [Reason]),
							DecodedPkt;
						_ -> ok
					end;
				{updated, _} ->
					spawn( %% spawn because this function is called from the room pid
						fun() ->
							eims:edit_history_msg(LUser, LHost, LServer, EditedOriginId, Body),
							eims:delete_from_history_by_id(LUser, LHost, LServer, [RetractId])
						end),
					DecodedPkt;
				E -> ?dbg("ERROR : ~p", [E]),
					DecodedPkt
			end
	end;
store(#fasten_apply_to{id = RetractId, sub_els = [#retract_id{}]}, [DecodedPkt, _, LServer, {LUser, LHost}, Type | _]) ->
	OriginId = get_oid_by_rid(RetractId, LServer),
	case ejabberd_sql:sql_query(ejabberd_router:host_of_route(LServer), %% retract message
		?SQL("delete from archive where %(LServer)H and retract_id = %(RetractId)s")) of
		{error, Reason} ->
			?dbg("ERROR: ~p", [Reason]),
			DecodedPkt;
		_ when Type == groupchat ->
			spawn(eims, delete_from_history_by_id, [LUser, LHost, LServer, [RetractId]]),
			DecodedPkt;
		_ ->
			eims_offline:remove_offline_msgs_by_tags([#origin_id{id = RetractId}, #origin_id{id = OriginId}, #replace{id = OriginId}]),
			DecodedPkt
	end;
store(#receipt_response{id = RetractId}, [DecodedPkt | [_Pkt, LServer | _] = TailData]) ->
	case get_oid_by_rid(RetractId, LServer) of
		{error, Reason} = Err ->
			?dbg("ERROR: ~p", [Reason]),
			DecodedPkt;
		OriginId ->
			erlang:apply(?MODULE, store, TailData ++ [OriginId, RetractId]),
			DecodedPkt
	end.
store(#xmlel{name = <<"message">>} = Pkt, LServer, {LUser, LHost}, Type, Peer, Nick, Dir, TS, OriginId, RetractId) ->
	SUser = case Type of
		        chat -> LUser;
		        groupchat -> jid:encode({LUser, LHost, <<>>})
	        end,
	BarePeer = jid:encode(
		jid:tolower(
			jid:remove_resource(Peer))),
	LPeer = jid:encode(
		jid:tolower(Peer)),
	Body = fxml:get_subtag_cdata(Pkt, <<"body">>),
	SType = misc:atom_to_binary(Type),
	SqlType = ejabberd_option:sql_type(LServer),
	XML = case mod_mam_opt:compress_xml(LServer) of
		      true ->
			      J1 = case Type of
				           chat -> jid:encode({LUser, LHost, <<>>});
				           groupchat -> SUser
			           end,
			      xml_compress:encode(Pkt, J1, LPeer);
		      _ ->
			      fxml:element_to_binary(Pkt)
	      end,
	case ejabberd_sql:sql_query(
		LServer,
		?SQL_INSERT(
			"archive",
			["username=%(SUser)s",
				"server_host=%(LServer)s",
				"timestamp=%(TS)d",
				"peer=%(LPeer)s",
				"bare_peer=%(BarePeer)s",
				"xml=%(XML)s",
				"txt=%(Body)s",
				"kind=%(SType)s",
				"origin_id=%(OriginId)s",
				"retract_id=%(RetractId)s",
				"nick=%(Nick)s"])) of
		{updated, _} ->
			xmpp:decode(Pkt);
		Err ->
			?DEBUG("ERROR: ~p", [Err]),
			xmpp:decode(Pkt)
	end.

tuple_to_msg(L) ->
	[#archive_msg{us = eims:string_to_usr(USa),                        %  :: {binary(), binary()},
		id = integer_to_binary(TS),                                           %  :: binary(),
		timestamp = eims:timestamp_to_now(TS),                             %  :: erlang:timestamp(),
		peer = jid:string_to_usr(Peer), bare_peer = jid:string_to_usr(BPeer), %  :: ljid() | undefined,
		packet = fxml_stream:parse_element(XML),                              %  :: xmlel() | message(),
		nick = Nick,                                                          %  :: binary(),
		type = erlang:binary_to_existing_atom(Type, utf8)}                    %  :: chat | groupchat}).<-L;
		|| {USa, Id, TS, Peer, BPeer, XML, Nick, Type} <- L].

decode_msgs(Msgs) ->
	[xmpp:decode(fxml_stream:parse_element(Msg)) || {Msg} <- Msgs].
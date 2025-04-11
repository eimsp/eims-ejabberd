-module(eims_mnesia).
-compile(export_all).
%% API
-export([]).

%%-include("logger.hrl").
-include_lib("xmpp/include/xmpp.hrl").
-include_lib("stdlib/include/qlc.hrl").
-include("mod_muc_room.hrl").
-include("mod_mam.hrl").
-include("eims.hrl").

%%remove_mam_for_user(Room, RoomHost, #jid{} = BarePeer) ->
%%	remove_mam_for_user(Room, RoomHost, jid:split(BarePeer), #archive_msg.bare_peer);
%%remove_mam_for_user(Room, RoomHost, Nick) ->
%%	remove_mam_for_user(Room, RoomHost, Nick, #archive_msg.nick).
%%remove_mam_for_user(Room, RoomHost, User, Pos) ->
%%	mnesia:transaction(
%%		fun() ->
%%			qlc:e(qlc:q(
%%				[begin
%%					 mnesia:delete_object(R),
%%					 [mnesia:delete_object(C) || C <- mnesia:index_read(mam_index, Id, id)]
%%				 end || R = #archive_msg{id = Id} <- mnesia:table(archive_msg),
%%					element(Pos, R) == User, R#archive_msg.us == {Room, RoomHost}]))
%%		end).

remove_mam_msgs(LUser, LServer, WithJid) ->
	mod_mam_mnesia:remove_from_archive(LUser, LServer, WithJid).

%%remove_mam_msg_by_ids(Room, RoomHost, Ids) ->
%%	mnesia:transaction(
%%		fun() ->
%%			qlc:e(qlc:q(
%%				[begin
%%					 mnesia:delete_object(R),
%%					 [mnesia:delete_object(C) || C <- mnesia:index_read(mam_index, Id, id)]
%%				 end || R = #archive_msg{id = Id} <- mnesia:table(archive_msg),
%%					R#archive_msg.us == {Room, RoomHost}, lists:member(R#archive_msg.id, Ids)]))
%%		end).

get_mam_by_nick({_Room, _RoomHost} = US,  Nick) ->
	case mnesia:transaction(
		fun() ->
			qlc:fold(
				fun(#archive_msg{us = US2, nick = Nick2, packet = Pkt} = MamMsg, Acc)
					when Nick2 == Nick, US == US2 ->
					[MamMsg#archive_msg{packet = xmpp:decode(Pkt)}|Acc];
					(_, Acc) -> Acc
				end, [], mnesia:table(archive_msg))
		end) of
		{atomic, MamMsgs} -> MamMsgs;
		Err -> Err
	end.

get_last_msg(_Conf, {error, _} = Err) ->
	Err;
get_last_msg({_Room, _RoomHost} = Conf, {User, Server}) ->
	get_last_msg(Conf, {User, Server, <<>>}, #archive_msg.bare_peer);
get_last_msg({_Room, _RoomHost} = Conf, #jid{luser = User, lserver = Server})  ->
	get_last_msg(Conf, {User, Server});
get_last_msg({_Room, _RoomHost} = Conf, Nick) when is_binary(Nick) ->
	get_last_msg(Conf, Nick, #archive_msg.nick).
get_last_msg({Room, RoomHost}, Param, Pos) ->
	case mnesia:transaction(
		fun() ->
			qlc:fold(
				fun(#archive_msg{us = US, id = Id, packet = Pkt} = ArcMsg, #archive_msg{id = Id2} = Acc)
					when US == {Room, RoomHost} ->
					case element(Pos, ArcMsg) of
						Param ->
							#message{body = Body} = xmpp:decode(Pkt),
							case Id > Id2 andalso Body /= [] of true -> ArcMsg; _ -> Acc end;
						_ ->
							Acc
					end;
					(_, Acc) -> Acc
				end, #archive_msg{id = 0}, mnesia:table(archive_msg))
		end) of
		{atomic, #archive_msg{id = 0}} -> {error, not_found};
		{atomic, Msg} -> Msg;
		Err -> Err
	end.

get_last_msgs({_Room, _RoomHost} = US, Number) ->
	get_last_msgs({_Room, _RoomHost} = US, Number, fun(_) -> true end).
get_last_msgs({_Room, _RoomHost} = US, Number, Pred) when is_function(Pred) ->
	case mnesia:transaction(
		fun() ->
			HQ = qlc:q([MamMsg || #archive_msg{nick = _Nick2, us = US2} = MamMsg
				<- mnesia:table(archive_msg), Pred(MamMsg), US == US2]),
			HQ2 = qlc:sort(HQ, {order, fun(#archive_msg{id = Id}, #archive_msg{id = Id2}) -> Id > Id2 end}),
			qlc:fold(fun(MamMsg, Acc) when length(Acc) < Number -> [MamMsg|Acc];
				(_, Acc) -> Acc end, [], HQ2)
		end) of
		{atomic, MamMsgs} -> MamMsgs;
		Err -> Err
	end;
get_last_msgs({_Room, _RoomHost} = US, Number, #jid{} = Jid) ->
	BareJid = jid:split(Jid),
	get_last_msgs({_Room, _RoomHost} = US, Number, fun(#archive_msg{bare_peer = BareJid2}) -> BareJid2 == BareJid end);
get_last_msgs({_Room, _RoomHost} = US, Number, Nick) ->
	get_last_msgs({_Room, _RoomHost} = US, Number, fun(#archive_msg{nick = Nick2}) -> Nick2 == Nick end).

get_mam_msg_by_id({_User, _Host} = US, Id) ->
	case mnesia:transaction(
		fun() ->
			qlc:e(qlc:q([R || R <- mnesia:table(archive_msg),
				R#archive_msg.us == US, R#archive_msg.id == Id]))
		end) of
		{atomic, [#archive_msg{} = ArcMsg]} -> ArcMsg;
		{atomic, []} -> {error, not_found};
		{atomic, [_|_] = _MamMsgs} -> {error, multiple_messages};
		Err -> Err
	end.

edit_mam_msg_by_id({_User, _Host} = US, Id, Text) ->
	case mnesia:transaction(
		fun() ->
			qlc:e(qlc:q(
				[begin
					 #archive_msg{packet = Msg} = R,
					 mnesia:delete_object(R),
					 mnesia:write(R2 = R#archive_msg{packet =
					    xmpp:encode((xmpp:decode(Msg))#message{body = [#text{data = Text}]})}),
					 R2
				 end || R <- mnesia:table(archive_msg),
					R#archive_msg.us == US, R#archive_msg.id == Id]))
		end) of
		{atomic, [#archive_msg{} = ArcMsg]} -> ArcMsg;
		{atomic, []} -> {error, not_found};
		Err -> Err
	end.

%% mnesia utils
%%upd_record_fields(Record, I, [_ | _] = Defaults) ->
%%	{L, L2} = lists:split(I, tuple_to_list(Record)),
%%	list_to_tuple(L ++ Defaults ++ L2).

upd_record_fields(Record, I, [_ | _] = Defaults) ->
	{L, L2} = lists:split(I, tuple_to_list(Record)),
	list_to_tuple(L ++ Defaults).

upd_record(Record, I, Default) ->
	upd_record_fields(Record, I, [Default]).

up_table(RecName, OldArity, NewArity, TransformFun) ->
	case mnesia:table_info(RecName, arity) of
		OldArity ->
			TransformFun();
		NewArity ->
			?dbg("~p:migration:already updated", [?MODULE]), ok;
		OtherArity ->
			?dbg("~p:migration:unexpected:ariry:~p", [?MODULE, OtherArity]) end, ok.

%%upd_rec_by_key(Table, Key, Record) ->
%%	mnesia:read(Table,Key),

	migrate() -> backup(), migresia:migrate().

%% Mnesia cluster backup
%%
backup()-> ExcTabs= [], %% TODO exclude tables if backup
	backup(mnesia:system_info(tables)--ExcTabs).

backup(Tabs) ->
	Date = eims:local_time_as_gmt(calendar:local_time()),
	Node = node(),
%	{ok, ServerAddress} = vox_api:get_server_ip(),
	File = io_lib:format("./~s_bkp_~s", [Node, Date]),
	backup(false, Tabs, Node, File, []).

backup(Schema, Tables, Node, File, Opts) when is_list(Tables) ->
	Tabs = Tables -- if Schema -> []; true -> [schema] end,
	Opts2 = lists:keystore(max, 1, Opts, {max, Tabs}),
	case mnesia:activate_checkpoint(Opts2) of
		{ok, Name, _Nodes} ->
			case mnesia:backup_checkpoint(Name, File) of
				ok ->
					mnesia:deactivate_checkpoint(Name), ok;
				{error, Reason} = Err ->
					?dbg("~p: error: ~p", [?MODULE, Reason]),
					mnesia:deactivate_checkpoint(Name),
					Err
			end;
		{error, {"Cannot prepare checkpoint (replica not available)", [Table, _]}} ->
			backup(Schema, Tables -- [Table], Node, File, Opts);
		{error, Reason} = Err ->
			?dbg("~p: error: ~p", [?MODULE, Reason]),
			Err
	end.

restore(File) -> restore(File, node(), []).
restore(File, Node, SkipTbs) ->
	application:stop(bpe),
	case mnesia:restore(File, [{skip_tables, SkipTbs}]) of
		{aborted, {no_exists, Tab}} -> restore(File, Node, [Tab | SkipTbs]);
		{aborted, Reason} ->
			?dbg("~p: error: aborted backup restore from ~s by reason ~p", [?MODULE, File, Reason]),
			{error, Reason};
		{atomic, Tabs} ->
			{ok, Tabs};
		E -> E end.

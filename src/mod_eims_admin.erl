%%%-------------------------------------------------------------------
%%% @doc
%%% admin module for EIMS rooms
%%% @end
%%%-------------------------------------------------------------------
-module(mod_eims_admin).
-compile(export_all).
-behaviour(gen_mod).

%% API
-export([]).

-include("logger.hrl").
-include_lib("xmpp/include/xmpp.hrl").
-include("translate.hrl").
-include("mod_muc_room.hrl").
-include("mod_mam.hrl").
-include("eims.hrl").

-define(RETRACT_NUM, 20).

-callback remove_mam_for_user(binary(), binary(), binary() ) -> ok | {error, any()}.
-callback remove_mam_msg_by_ids(binary(), binary(), [binary()] ) -> ok | {error, any()}.
-callback remove_mam_msgs(binary(), binary(), jid() | none) -> ok | {error, any()}.
-callback read_archive(binary(), binary(), tuple()) -> list() | error.
-callback get_last_msgs(tuple(), integer(), binary() | #jid{} ) -> list() | {error, any()} | error.
-callback get_last_msgs(tuple(), integer()) -> list() | {error, any()} | error.
-callback edit_mam_msg_by_id(tuple(), binary(), binary())-> #archive_msg{} | {error, any()}.
-callback edit_mammsg_by_oid(atom(), tuple(), tuple(), binary())-> #archive_msg{} | {error, any()}.
-callback get_mam_msg_by_id(tuple(), binary())-> #archive_msg{} | {error, any()}.

cmds() -> %% valid admin commands
	Common = #{common => true}, %% room access by default
	[#cmd{name = ?help, doc = <<"[cmd] [doc] = set command doc text for admins\n//help [cmd] = set command doc text to default">>,
			deep = 3, default = [undefined, undefined], acl = all, room_access = Common#{rfq => true}},
		#cmd{name = ?admin, doc = <<"[nick] (set nick as admin for groupchat)">>, default = [<<"by admin">>], deep = 3, acl = moderator},
		#cmd{name = ?member, doc = <<"[nick] (set nick as member for groupchat)">>, default = [<<"by admin">>], deep = 3, acl = admin},
		#cmd{name = ?mute, doc = <<"[nick] (set nick as visitor for groupchat)">>, default = [<<"by admin">>], deep = 3, acl = moderator},
		#cmd{name = ?kick, doc = <<"[nick] [reason] (kick user from groupchat)">>, default = [<<"by admin">>], deep = 3, acl = moderator},
%%		#cmd{name = ?rban, doc = <<" [nick] [reason] (ban user in room)">>, default = [<<"by admin">>], deep = 3, acl = moderator},
%%		#cmd{name = ?runban, doc = <<" [nick] (unban user in room)">>, deep = 2, acl = moderator},
		#cmd{name = ?purge, doc = <<"[jid | nick | all], [none | kick] (purge messages in groupchat)">>, default = [<<"all">>, <<"none">>], deep = 3, acl = admin},
		#cmd{name = ?stats, doc = <<" command stats for whale. users">>, deep = 1, acl = moderator},
%%		#cmd{name = ?delmsg, doc = <<"[id] (delete message by id)">>, deep = 2, acl = moderator},
		#cmd{name = ?ban, doc = <<"[nick | jid] [\"all\" for ban all accounts] [reason] = ban account">>, deep = 4, default = [<<"only">>, <<"by admin">>], acl = admin},
		#cmd{name = ?unban, doc = <<"[nick | jid] [\"all\" for unban main account using subaccount`s nick or jid] = unban account">>, deep = 3, default = [ ], acl = admin},
		#cmd{name = ?banned, doc = <<" = list of banned users">>, acl = admin},
%%		#cmd{name = ?tv, doc = <<"[24h | 7d | 30d | all] = trade volumes last 24 hours or 7 days or 30 days or all time">>, default = [help], deep = 2, acl = all, broadcast = true},
		#cmd{name = ?iserv_auth, doc = <<"[scope] = url for integrated service authorization">>, deep = 2, default = [<<"block_trade:read_write account:read">>], acl = moderator},
		#cmd{name = ?user, doc = <<"[nick | jid] = account info or [set] [nick] = set own nick">>, default = [], deep = 3, acl = moderator, data = []},
	  #cmd{name = ?account, doc = <<"[role] [admin | user | none] [jid | nick]= add role ">>, default = [], deep = 4, acl = moderator, data = []},
		#cmd{name = ?edit, doc = <<"[text] = edit last message to new message">>, deep = 2, acl = all},
		#cmd{name = ?del, doc = <<"= delete last message">>, deep = 1, acl = all},
		#cmd{name = ?badwords, doc = <<"[ en | ru | ...] [bad word] (add word to or show link to selected blacklist)">>, deep = 3, acl = admin},
		#cmd{name = ?post, doc = <<"[comma separated rooms] [text] (send message to room)">>, deep = 3, acl = moderator},
		#cmd{name = ?muc, doc = <<"[priv | pub | del] [title | room_node](delete if del or create room as private or public)">>,
			default = [<<"priv">>, <<>>], deep = 3, acl = admin},
		#cmd{name = ?file_rm, doc = <<"[url] (delete uploaded file by url)">>, deep = 2, acl = moderator},
		#cmd{name = ?iserv_sub, doc = <<"[channel] (subscribe to the integrated service channel)">>, deep = 2, acl = moderator, broadcast = false, data = #{access_token => true}},
		#cmd{name = ?upd, doc = <<"$[command] [text | command] = update info command or alias for other command\n/upd$[command] =  delete command">>, default = [del], deep = 3, acl = admin} |
		mdrfq_umarket:cmd()].

start(Host, _Opts) ->
	eims:start(Host,_Opts),
	eims_offline:start(Host),
	ejabberd_hooks:add(sm_remove_connection_hook, Host, ?MODULE, user_offline, 120),
	ejabberd_hooks:add(user_send_packet, Host, ?MODULE, user_send_packet, 87),
	ejabberd_hooks:add(user_receive_packet, Host, ?MODULE, user_receive_packet, 87),
	ejabberd_hooks:add(muc_filter_message, Host, ?MODULE, muc_filter_message, 49),
	eims_db:start(Host).

stop(Host) ->
	eims:stop(Host),
	eims_offline:stop(Host),
	ejabberd_hooks:delete(sm_remove_connection_hook, Host, ?MODULE, user_offline, 120),
	ejabberd_hooks:delete(user_send_packet, Host, ?MODULE, user_send_packet, 87),
	ejabberd_hooks:delete(user_receive_packet, Host, ?MODULE, user_receive_packet, 87),
	ejabberd_hooks:delete(muc_filter_message, Host, ?MODULE, muc_filter_message, 49),
	eims_db:stop(Host),
	eims_offline:stop(Host).

mod_options(_Host) ->
	[{oauth_dialog, true},
		{ws_port, 443},
		{ws_resource, "/ws/api/v2"},
		{bot_nick, <<"EIMSBot">>},
		{bot_component, <<"eims.localhost">>},
		{fix_filters, [{<<"default">>, <<".*">>}]}
	].

mod_opt_type(oauth_dialog) ->
	econf:bool();
mod_opt_type(ws_port) ->
	econf:int();
mod_opt_type(ws_resource) ->
	econf:string();
mod_opt_type(bot_nick) ->
	econf:binary();
mod_opt_type(bot_component) ->
	econf:binary();
mod_opt_type(fix_filters) ->
	econf:map(econf:binary(), econf:binary(), [unique]);
mod_opt_type(_) -> [oauth_dialog, ws_port, ws_resource, bot_nick, bot_component, fix_filters].


mod_doc() ->
	#{desc => ?T("eims admin params"), opts =>
	[{oauth_dialog,
		#{value => ?T("OAuthDialog"),
			desc => ?T("By default OAuth dialog form is enabled. "
			"To disable set parameter as false")}},
		{ws_port,
			#{value => ?T("Web Socket eims port"),
				desc => ?T("By default port is 443.")}},
		{ws_resource,
			#{value => ?T("Web Socket eims resource"),
				desc => ?T("By default resiurce is /ws/api/v2.")}},
		{bot_nick,
			#{value => ?T("System Bot nick"),
				desc => ?T("By default EIMSBot")}},
		{bot_component,
			#{value => ?T("System Bot component"),
				desc => ?T("By default eims.localhost")}},
		{fix_filters,
			#{value => ?T("FIX filters"),
				desc => ?T("By default [{default, \".*\"}]")}}
		]}.

depends(_Host, _Opts) ->
	[].

user_offline(_SID, #jid{luser = User, lserver = Host} = JID, _Info) ->
	case ejabberd_sm:get_user_resources(User, Host) of
		[] -> eims:drop_tokens(JID); %% cancel refresh token timer
		_ -> ok
	end.

-spec muc_filter_message(message(), mod_muc_room:state(),
	binary()) -> message().
muc_filter_message(#message{body = [_ | _], to = #jid{luser = Room, lserver = RoomHost}, meta = Meta} = Pkt, _MUCState, _FromNick) ->
	case xmpp:get_subtag(Pkt, #replace{}) of
		#replace{id = ReplacedId} ->
			case eims_db:select_by_query(groupchat, {Room, RoomHost}, [{with_origin_id, ReplacedId}, {withtext, not_empty}]) of
				[#archive_msg{id = ReplaceTS}] ->
					Pkt#message{meta = Meta#{stanza_id => binary_to_integer(ReplaceTS)}};
				[] ->
					?DEBUG("ERROR: archive message with ~p id not found\n~p", [ReplacedId]),
					Pkt
			end;
		_ ->
			Pkt
	end;
muc_filter_message(Acc, _MUCState, _FromNick) ->
	Acc.

user_send_packet({#presence{type = available, from = #jid{user = <<"whale.", _/binary>>, lserver = _Host} = _From,
	to = #jid{luser = _Room, server = <<"conference.", _/binary>> = _RoomHost} = _To,
	sub_els = _S}, #{jid := _JID} = _C2SState} = Packet) ->
	Packet;
user_send_packet({#presence{type = available, from = #jid{luser = User, lserver = Host} = _From,
	to = #jid{user = Room, server = <<"conference.", _/binary>> = RoomHost}} = _Pkt, _C2SState} = Packet) ->
	case catch mod_muc_admin:get_room_affiliations(Room, RoomHost) of
		{error, _} -> ok;
		{'EXIT', _} -> ok;
		Affs ->
			case lists:keyfind(User, 1, Affs) of
				{_, _, A, _} when A == owner; A == admin -> ok;
				_ ->
					catch mod_muc_admin:set_room_affiliation(Room, RoomHost, <<User/binary, "@", Host/binary>>, <<"admin">>)
			end
	end,
	Packet;
user_send_packet({#message{type = chat, to = #jid{lserver = Server, resource = Resource},
						   body = [#text{data = <<"/", _Cmd/binary>>}], meta = Meta} = Pkt, C2SState} = _Packet) ->
	Host = eims:host(),
	MucHost = eims:muc_host(),
	BotNick = eims:bot_nick(),
	case Server of
		Host ->
			{stop, {drop, C2SState}}; %% TODO temporary not allowed commands for p2p
		MucHost when Resource == BotNick ->
			user_send_packet({Pkt#message{type = groupchat, meta = Meta#{orig_pkt => Pkt}}, C2SState}); %% TODO only for rfq?
		MucHost ->
			{stop, {drop, C2SState}}; %% TODO temporary not allowed private commands for p2p to common users
		_ ->
			{Pkt, C2SState}
	end;
user_send_packet({#message{type = groupchat,
	body = [T = #text{data = <<"//", Cmd/binary>>}]} = Pkt, C2SState}) ->
	user_send_packet({Pkt#message{body = [T#text{data = <<"/", Cmd/binary>>}]}, C2SState});
user_send_packet({#message{type = groupchat, body = [#text{data = <<"/", _Cmd/binary>>}], meta = Meta} = Pkt, C2SState}) ->
	OrigPkt = #message{meta = OrigMeta} = case Meta of #{orig_pkt := P} -> P; _ -> Pkt end,
	PrevPkt = OrigPkt#message{meta = OrigMeta#{prev_pkt => OrigPkt}},
	StopDrop = {stop, {drop, C2SState}},
	case catch exec_cmd(eims:increment_stats(acl(init_cmd(PrevPkt, is_map_key(custom, C2SState))))) of
		{error, custom_alias}  ->
			eims:send_edit(PrevPkt, <<"Alias for custom command is detected. Command cannot be executed.">>),
			StopDrop;
		{error, Reason}  ->
			eims:send_error(PrevPkt, Reason),
			StopDrop;
		#cmd{context = NewPkt, custom = true} ->
			case user_send_packet({NewPkt, C2SState#{custom => true}}) of
				{stop, {drop, _}} ->
					StopDrop;
				{Pkt2, _} ->
					eims:send_msg(Pkt2),
					StopDrop
			end;
		_ ->
			StopDrop
	end;
user_send_packet({#message{type = chat} = Pkt, C2SState} = Packet) ->
	MucHost = ?MUC_HOST,
	case Pkt of
		#message{to = #jid{luser = <<"rfq.", _/binary>>, user = RoomName, server = MucHost, resource = Nick}} ->
			{_, #state{users = Users} = State} = eims:get_state(RoomName, MucHost),
			case eims:subscriber_jid(Nick, State) of
				#jid{} -> Packet;
				_ -> case map_size(maps:filtermap(fun(_LJID, #user{nick = N}) -> N == Nick end, Users)) of
					     0 -> {xmpp:set_subtag(Pkt, #hint{type = 'no-store'}), C2SState};
					     N -> Packet
				     end
			end;
		_ -> Packet
	end;
user_send_packet(Packet) ->
	Packet.

user_receive_packet({#message{type = Type} = Pkt, C2SState}) ->
	Pkt2 = case Type == groupchat andalso xmpp:has_subtag(Pkt, #replace{}) of
		       true -> xmpp:remove_subtag(Pkt, #stanza_id{});
		       _ -> Pkt
	       end,
	{case xmpp:get_subtag(Pkt2, #bot{}) of
		 #bot{} = Bot -> xmpp:set_subtag(Pkt2, Bot#bot{hash = <<>>});
		 _ -> Pkt2
	 end, C2SState};
user_receive_packet(Packet) ->
	Packet.

init_cmd(#message{body = [#text{data = <<"/upd$", CmdText/binary>>}]} = Pkt, IsCustom) ->
	init_cmd(Pkt#message{body = [#text{data = <<"/upd ", CmdText/binary>>}]}, IsCustom);
init_cmd(#message{body = [#text{data = <<"/", CmdTextDirty/binary>>}], meta = Meta} = Pkt, IsCustom) ->
	CmdText = list_to_binary(string:strip(binary_to_list(CmdTextDirty))),
	{Broadcast, CmdText2} =
		case CmdText of <<"!", CmdTextTmp/binary>> -> {true, CmdTextTmp}; _ -> {false, CmdText} end,
	case binary:split(CmdText2, <<" ">>) of
		[Cmd | T] ->
			case lists:keyfind(Cmd, #cmd.name, cmds()) of
				#cmd{deep = Deep, default = Default, broadcast = B, args_format = ArgsFormat} = CmdR ->
					ArgFun =
						fun ArgFun(ArgsFormatTmp) ->
							{Deep2, Default2, ReOptions} =
								case ArgsFormatTmp of
									#{json := _} -> {2, [], []};
									_ -> {Deep, Default, [global]}
								end,
							NCmdText = list_to_binary(re:replace(CmdText2, "(\\s+\\s+)", " ", [{return, list}] ++ ReOptions)),
							Pkt2 = Pkt#message{meta = Meta#{command => Cmd}},
							CmdR2 = CmdR#cmd{context = Pkt#message{meta = Meta#{command => Cmd}}, broadcast = if B -> Broadcast; true -> B end},
							case {eims:split(NCmdText, Deep2, Default2), ArgsFormatTmp} of
								{[Name, <<${, _/binary>> = Json], #{json := _}} ->
									case catch jiffy:decode(Json, [return_maps]) of
										#{} = JsonMap ->
											DefaultJson = case Default of #{json := #{} = D} -> D; _ -> #{} end,
											CmdR2#cmd{name = Name, args = [maps:merge(DefaultJson, JsonMap)]};
										_ ->
											{error, invalid_json_parameter}
									end;
								{[_Name, _], #{json := _}} ->
									ArgFun(maps:remove(json, ArgsFormatTmp));
								{[Name | Args], #{plane := _}} ->
									CmdR2#cmd{name = Name, args = Args};
								_ ->
									eims:send_edit(Pkt2, <<"Invalid /", CmdText2/binary, " command">>),
									{error, invalid_cmd}
							end
						end,
					ArgFun(ArgsFormat);
				false when T == [] ->
					#cmd{name = Cmd, deep = 1, context = Pkt, custom = IsCustom, acl = moderator};
				_ ->
					eims:send_edit(Pkt, <<"Invalid /", CmdText2/binary, " command">>),
					{error, invalid_cmd}
			end
	end.

%%  Execution of commands

exec_cmd({error, invalid_params, #cmd{name = Name, context = Pkt}}) ->
	eims:send_edit(Pkt, <<"Invalid params for /", Name/binary, " command">>);
exec_cmd({error, invalid_cmd, #cmd{name = Name, context = Pkt}}) ->
	eims:send_edit(Pkt, <<"Invalid /", Name/binary, " command">>);
exec_cmd(#cmd{acl = custom} = Cmd) ->
	Cmd;
exec_cmd(#cmd{args = [help | _], context = Pkt} = Cmd) ->
	eims:send_edit(Pkt, eims_format:help_format(Cmd));
exec_cmd(#cmd{name = ?mute} = Cmd) ->
	exec_cmd(Cmd#cmd{name = <<"none">>});
exec_cmd(#cmd{name = CmdName, args = [PeerNick, _Reason],
	context = #message{to = #jid{luser = Room, lserver = RoomHost}} = Pkt})
		when CmdName == ?admin; CmdName == ?member; CmdName == <<"none">> ->
	Occupants = mod_muc_admin:get_room_occupants(Room, RoomHost),
	case lists:keyfind(PeerNick, 2, Occupants) of
		{Jid, _, _} ->
			mod_muc_admin:set_room_affiliation(Room, RoomHost,
				jid:encode(jid:remove_resource(jid:decode(Jid))), CmdName);
		_ ->
			?DEBUG("Occupant ~s not found", [PeerNick]),
			eims:send_edit(Pkt, <<"Occupant \"", PeerNick/binary, "\" not found in the room">>)
	end;
exec_cmd(#cmd{name = ?file_rm, args = [Url], context = Pkt}) ->
	Host = eims:host(),
	GetUrlTemplate =
		case mod_http_upload_opt:get_url(Host) of
			undefined -> mod_http_upload_opt:put_url(Host);
			GUrl -> GUrl
		end,
	Msg =
		try
			{TemplatePath, UrlTemplateMap} = maps:take(path, uri_string:parse(binary:replace(GetUrlTemplate, <<"@HOST@">>, Host))),
			UrlMap = #{path := Path} = uri_string:parse(Url),
			Port = maps:find(port, UrlTemplateMap),
			case maps:find(port, UrlMap) of
				Port ->
					UrlTemplateMap = maps:intersect(UrlTemplateMap, UrlMap),
					End = size(TemplatePath),
					{0, End} = binary:match(Path, TemplatePath),
					<<"/", RelPath/binary>> = binary:part(Path, End, size(Path) - End),
					[User, _, _] = SplitedPath = filename:split(RelPath),
					case Pkt of
						#jid{luser = <<"whale.", _/binary>>} = From ->
							User = eims:make_user_string(From), []; %% check user remove own uploaded file
						_ -> ok
					end,
					[] = [ok || <<"..">> <- SplitedPath], %% checks if the file path is relative to the parent directory and has 3 elements
					FileName = filename:join(mod_http_upload_opt:docroot(Host), RelPath),
					DirName = filename:dirname(FileName),
					case file:del_dir_r(binary_to_list(DirName)) of
						ok ->
							<<"File successfully deleted">>;
						{error, Error} when Error == enotdir; Error == enoent ->
							?dbg("Found no HTTP upload directory of ~s", [FileName]),
							<<"File not found">>;
						{error, Error} ->
							?dbg("Cannot remove HTTP upload directory ~s : ~p", [FileName, Error]),
							<<"Can't delete file. Try later">>
					end;
				_ -> ?DEBUG("ERROR: invalid url port: ~p", [Port]),
					<<"Invalid url port">>
			end
		catch
			_ : {badmatch, _} -> <<"Invalid url">>;
			_ : E ->
				?ERROR_MSG("Internal error: ~p", [E]),
				<<"Invalid url">>
		end,
	eims:send_edit(Pkt, Msg);
exec_cmd(#cmd{name = ?purge, args = [<<"all">>, <<"none">>],
	context = #message{from = #jid{lserver = Host}, to = #jid{luser = Room, lserver = MucHost} = To} = Pkt}) ->
	spawn(
		fun() ->
			Pkts = eims_sql:select_messages_like_bare_peer(jid:encode(jid:remove_resource(To))),
			[eims:send_retract(MamMsg) || #archive_msg{} = MamMsg <- eims_db:get_last_msgs({Room, MucHost}, ?RETRACT_NUM)],
			eims_db:remove_from_archive_with_bare_peer(To),
			Text =
				case eims_db:remove_mam_msgs(Room, MucHost, none) of
					ok ->
						eims:clear_room_history(Room, MucHost, Host),
						Pkts2 = lists:ukeysort(#message.id, lists:reverse(Pkts)),
						[begin
								 #origin_id{id = OriginId} = xmpp:get_subtag(P, #origin_id{}),
								 Id = eims:gen_uuid(),
								 P2 = P#message{id = Id, body = [],
									 sub_els = [#offline{}, #hint{type = 'no-store'}, #origin_id{id = Id},
										 #fasten_apply_to{id = OriginId, sub_els = [#retract_id{}]}]},
								 eims:route(P2)
						 end || #message{type = chat} = P <- Pkts2],
						eims_offline:remove_all_private_msgs(To),
						"all messages have been deleted successfully";
					E -> ?DEBUG("purge command is failed: ~p", [E]),
						"purge command is failed"
				end,
			eims:send_edit(Pkt, Text)
		end);
exec_cmd(#cmd{name = ?purge, args = [JidOrNick, Action],
	context = #message{from = #jid{lserver = Host}, to = #jid{luser = Room, lserver = RoomHost} = To} = Pkt}) ->
	Text =
		case eims:get_jid_by_priv_data(JidOrNick, {Room, RoomHost}) of
			{error, jid_not_found} ->
				<<"user ", JidOrNick/binary, " not found">>;
			#eims_storage{jid = #jid{} = Jid} ->
				Msg =
					case eims_db:get_last_msg({Room, RoomHost}, Jid) of
						#archive_msg{} ->
							[eims:send_retract(MamMsg) || #archive_msg{} = MamMsg <-
								eims_db:get_last_msgs({Room, RoomHost}, ?RETRACT_NUM, Jid)],
							case eims_db:remove_mam_for_user(Room, RoomHost, Jid) of
								ok -> eims:clear_room_history(Room, RoomHost, Host, Jid),
									<<JidOrNick/binary, " messages have been deleted successfully">>;
								E -> ?DEBUG("purge command is failed: ~p", [E]),
									<<"purge command is failed">>
							end;
						{error, not_found} ->
							<<JidOrNick/binary, " messages have been deleted successfully">>;
						{error, jid_not_found} ->
							<<"messages of user ", JidOrNick/binary, " not found">>;
						Err ->
							?DEBUG("purge command is failed: ~p", [Err]),
							<<"purge command is failed">>
					end,
				case Action of
					<<"kick">> ->
						Pkts = eims_sql:select_private_messages_from_archive(Jid, jid:remove_resource(To)),
						mod_mam:remove_mam_for_user_with_peer(Jid#jid.user, Host, jid:encode(To)),
						[begin
							 #origin_id{id = OriginId} = xmpp:get_subtag(P, #origin_id{}),
							 mod_muc:route(P#message{id = <<>>, body = [], sub_els = [#hint{type = store}, #origin_id{id = eims:gen_uuid()},
								 #fasten_apply_to{id = OriginId, sub_els = [#retract_id{}]}]})
						 end || P <- Pkts],
						{ok, Pid} = mod_muc:unhibernate_room(Host, RoomHost, Room),
						mod_muc_room:unsubscribe(Pid, Jid),
						[mod_muc_room:change_item_async(Pid, Jid, AffOrRole, none, <<"User removed">>) || AffOrRole <- [role, affiliation]];
					_ -> ok
				end,
				Msg
		end,
	eims:send_edit(Pkt, Text);
exec_cmd(#cmd{name = ?stats, args = [],	context = #message{} = Pkt}) ->
	Text =
		lists:foldl(
			fun(Name, Acc) ->
				case mnesia:dirty_read(eims_cmd, Name) of
					[#eims_cmd{acl = all, type = base, stats = Stats}] ->
						<<Acc/binary, "\n\t/", Name/binary, "\t", (integer_to_binary(Stats))/binary>>;
					_ -> Acc
				end
			end, <<"Command stats for whale. users:">>, mnesia:dirty_all_keys(eims_cmd)),
	eims:send_edit(Pkt, Text);

exec_cmd(#cmd{name = ?delmsg, args = [MamId],
	context = #message{to = #jid{luser = Room, lserver = RoomHost}} = Pkt}) ->
	Text =
		case eims_db:get_mam_msg_by_id({Room, RoomHost}, MamId) of
			#archive_msg{id = MamId} = MamMsg ->
				eims_db:remove_mam_msg_by_ids(Room, RoomHost, [MamId]),
				eims:send_retract(MamMsg),
				<<"the message ", MamId/binary, " is deleted">>;
			{error, not_found} ->
				<<"the message ", MamId/binary, " not found">>;
			{error, _} ->
				<<"the message ", MamId/binary, " could not be deleted due to an internal error">>
		end,
	eims:send_edit(Pkt, Text);
exec_cmd(#cmd{name = CmdName, args = [PeerNick, Reason],
	context = #message{from = #jid{} = From, to = #jid{luser = Room, lserver = Host} = To} = Pkt})
	when CmdName == ?kick; CmdName == ?rban ->
	case lists:keyfind(PeerNick, 2, mod_muc_admin:get_room_occupants(Room, Host)) of
		false -> eims:send_edit(Pkt, <<"User \"", PeerNick/binary, "\" not found in this groupchat">>);
		_ ->
			Item = case CmdName of
				       <<"kick">> -> #muc_item{role = none};
				       ?rban -> #muc_item{affiliation = outcast}
			       end,
			Stanza = #iq{type = set, from = From, to = To,
				sub_els = [#muc_admin{items = [Item#muc_item{reason = Reason, nick = PeerNick}]}]},
			ejabberd_router:route(Stanza)
	end;
exec_cmd(#cmd{name = ?runban, args = [U],
	context = #message{from = #jid{lserver = Host}, to = #jid{luser = Room, lserver = RoomHost}}}) ->
	mod_muc_admin:set_room_affiliation(Room, RoomHost, <<U/binary, "@", Host/binary>>, <<"none">>);
exec_cmd(#cmd{name = Cmd, args = Args, context = #message{from = From, to = #jid{luser = Room, lserver = RoomHost}} = Pkt})
	when Cmd == ?del andalso Args == [] orelse Cmd == ?edit andalso Args /= [] ->
	case eims_sql:get_last_msgs({Room, RoomHost}, 1, From) of
		[#archive_msg{packet = Packet}] ->
			case xmpp:get_subtag(DecodedPkt = xmpp:decode(Packet), #origin_id{}) of
				#origin_id{id = RetractId} ->
					Id = eims:gen_uuid(),
					Pkt2 =
						case Cmd of
							?del -> Pkt#message{id = Id, body = [],
								sub_els = [#origin_id{id = Id}, #hint{type = store}, #fasten_apply_to{id = RetractId, sub_els = [#retract_id{}]}]};
							?edit ->
								ReplaceId =
									case xmpp:get_subtag(DecodedPkt, #replace{}) of
										#replace{id = OriginId} -> OriginId;
										_ -> RetractId
									end,
								Lang = mod_pottymouth:getMessageLang(Pkt),
								FilteredMessageWords = binary:list_to_bin(mod_pottymouth:filterMessageText(Lang, binary:bin_to_list(hd(Args)))),
								Pkt#message{id = Id, body = [#text{data = FilteredMessageWords, lang = xmpp:get_lang(Pkt)}],
									sub_els = [#origin_id{id = Id}, #chatstate{type = active}, #replace{id = ReplaceId}]}
						end,
					mod_muc:route(Pkt2);
				_ ->
					?DEBUG("ERROR: invalid packet: ~p", [Packet]),
					eims:send_edit(Pkt, <<"Internal error">>)
			end;
		{error, not_found} -> eims:send_edit(Pkt, <<"last message not found">>)
	end;
%%exec_cmd(#cmd{name = ?ban, args = [#eims_storage{jid = #jid{}} = UserStorage, <<"all">>, Reason]} = Cmd) ->
%%	[exec_cmd(Cmd#cmd{args = [SubAccount#eims_storage{jid = jid:make(U, S), access = deny},
%%		<<"only">>, Reason], data = loop}) ||
%%			#eims_storage{jid = {U, S}} = SubAccount <- eims:get_all_accounts(UserStorage)];
%%exec_cmd(#cmd{name = ?ban, args = [#eims_storage{id = MainId, main_account_id = MainId} = UserStorage,
%%		_AllOrOnly, Reason], data = Data} = Cmd) when Data /= loop ->
%%	exec_cmd(Cmd#cmd{args = [#eims_storage{jid = #jid{}} = UserStorage, <<"all">>, Reason], data = loop});
exec_cmd(#cmd{name = ?ban, context = _Pkt, args = [#eims_storage{jid = #jid{luser = _U, lserver = S},
	main_account_id = MainId, nick = Nick}, <<"all">>, Reason]} = Cmd) ->
	MId = integer_to_binary(MainId),
	case mnesia:dirty_index_read(eims_storage, MainId, id) of
		[#eims_storage{jid = {MU, MS}} = Storage] ->
			exec_cmd(Cmd#cmd{name = ?ban,
				args = [Storage#eims_storage{jid = #jid{luser = MU, lserver = MS}}, <<"only">>, Reason]});
		[] -> Store = #eims_storage{jid = {MId, S}, id = MainId, main_account_id = MainId, nick = Nick,
			access = deny, tstamp = os:timestamp()},
			mnesia:transaction(fun() -> mnesia:write(Store) end),
			exec_cmd(Cmd#cmd{name = ?ban,
				args = [Store#eims_storage{jid = #jid{luser = MId, lserver = S}}, <<"only">>, Reason]})
	end;
exec_cmd(#cmd{name = ?ban, context = Pkt, args = [#eims_storage{jid = #jid{luser = User, lserver = Server} = PeerJid,
		     id = Id, main_account_id = MainId}= UserStorage, _AllOrOnly, Reason], data = _Data}) ->
	%Deny = case Access of global_deny -> Access; _ -> deny end,
	mod_adhoc_eims:set_access(PeerJid, deny),
%	case Data of
%		 loop ->  Head = case Id of MainId -> <<"main ">>; _ -> <<"sub-">> end, eims:send_edit(Pkt, <<Head/binary, "account ", U/binary, "@", S/binary, " has been banned">>);
	Accounts =
		case Id of
			MainId ->
				lists:flatten([begin Head = case SId of MId -> <<"main ">>; _ -> <<"sub-">> end,
				<<Head/binary, "account ", U/binary, "@", S/binary>> end ||
					#eims_storage{jid = {U, S}, id = SId, main_account_id = MId, access = _Acc}
						<- eims:get_all_accounts(UserStorage), MId == MainId]);
			_ ->
				lists:flatten([begin Head = case SId of MId -> <<"main ">>; _ -> <<"sub-">> end,
				<<Head/binary, "account ", U/binary, "@", S/binary>> end ||
					#eims_storage{jid = {U, S}, id = SId, main_account_id = MId, access = deny}
						<- eims:get_all_accounts(UserStorage), MId == MainId])
		end,
	Banned = eims:binary_join([<<"banned accounts:">> | Accounts], <<"\n\t">>),
	eims:send_edit(Pkt, Banned),
%	end,
	[mod_admin_extra:kick_session(User, Server, Res, Reason) || Res <- ejabberd_sm:get_user_resources(User, Server)];
%%exec_cmd(#cmd{name = ?ban, args = [#eims_storage{} = UserStorage |_], data = Data} = Cmd) ->
%%	ct:pal("CMD Ban: ~p", [Cmd]),
%%	exec_cmd(Cmd#cmd{args = [#eims_storage{jid = #jid{}} = UserStorage, <<"only">>, <<" by moderator">>], data = loop});
exec_cmd(#cmd{name = ?unban, context = #message{} = Pkt,
	args = [#eims_storage{main_account_id = MainId, nick = Nick}, <<"all">>]}) ->
	%ct:pal("CMD UNBan: ~p", [Cmd]),
	case mnesia:dirty_index_read(eims_storage, MainId, id) of
		[#eims_storage{jid = {_MU, _MS}} = Storage] ->
			mnesia:dirty_write(Storage#eims_storage{access = allow, tstamp = 0}),
			eims:send_edit(Pkt, <<Nick/binary, "`s main account has been unbanned">>);
		_ -> {error, user_not_found}
  end;
exec_cmd(#cmd{name = ?unban, args = [#eims_storage{jid = #jid{} = PeerJid}]}) ->
	mod_adhoc_eims:remove_banned(PeerJid);
exec_cmd(#cmd{name = Name, args = [PeerJidNick | Params],
	context = #message{to = #jid{luser = Room, lserver = RoomHost}} = Pkt} = Cmd)
	when Name == ?ban; Name == ?unban ->
		case eims:get_jid_by_priv_data(PeerJidNick, {Room, RoomHost}) of
			#eims_storage{jid = #jid{}} = UserStorage ->
			  	exec_cmd(Cmd#cmd{args = [UserStorage | Params]}),
				  if (Name == ?unban) and (Params == []) ->
						                          eims:send_edit(Pkt, <<PeerJidNick/binary, " has been ", Name/binary, "ned">>);
					                                true -> false end;
			{error, _} ->
				eims:send_edit(Pkt, <<PeerJidNick/binary, " not found">>)
		end;
exec_cmd(#cmd{name = ?help, args = [undefined, undefined], context = #message{} = Pkt, data = Acl}) ->
	eims:send_edit(Pkt, eims_format:help_format(Acl, eims_format:help_pred_fun(Pkt)), bot);
exec_cmd(#cmd{name = ?help, args = [Name, undefined], context = #message{} = Pkt, data = Acl}) when Name /= undefined ->
	OutText =
		case mnesia:dirty_read(eims_cmd, Name) of
			[] -> <<"command not found">>;
			[#eims_cmd{type = base} = DCmd] when Acl == admin ->
				case lists:keyfind(Name, #cmd.name, cmds()) of
					#cmd{doc = Doc} ->
						mnesia:dirty_write(DCmd#eims_cmd{doc = Doc}),
						<<"base command doc text set to default">>;
					_ -> <<"base command not found">>
				end;
			[#eims_cmd{type = custom} = DCmd] when Acl == admin; Acl == moderator ->
				mnesia:dirty_write(DCmd#eims_cmd{doc = undefined}),
				<<"custom command doc text set to default">>;
			_ -> <<"access denied">>
		end,
	eims:send_edit(Pkt, <<" /",Name/binary, " ", OutText/binary>>);
exec_cmd(#cmd{name = ?help, args = [Name, Doc], context = #message{} = Pkt, data = all}) when Name /= undefined, Doc /= undefined ->
	eims:send_edit(Pkt, <<"access denied">>);
exec_cmd(#cmd{name = ?help, args = [Name, Doc], context = #message{} = Pkt, data = Acl})
	when Doc /= undefined ->
	Text =
		case {mnesia:dirty_read(eims_cmd, Name), Acl} of
			{[], _ }-> <<"command has not been found">>;
			{[#eims_cmd{type = Type} = Cmd], admin} when Acl == admin orelse (Type == custom andalso Acl == moderator) ->
				mnesia:dirty_write(Cmd#eims_cmd{doc = Doc}),
				<<"command doc is succesfully updated">>;
			_ ->
				<<"access denied">>
		end,
	eims:send_edit(Pkt, <<" /", Name/binary, " ", Text/binary>>);
exec_cmd(#cmd{name = ?iserv_auth, args = [Scope], context = #message{from = From, to = To} = Pkt}) ->
	eims:set_token_expired_time(jid:remove_resource(From), Nonce = eims:sys_time()),
	StateMap = #{jid => jid:encode(From), nonce => Nonce},
	StateMap2 = case To of undefined -> StateMap; _ -> StateMap#{groupchat => jid:encode(To)} end,
	State = uri_string:quote(base64:encode(term_to_binary(StateMap2))),
	AuthUrl = eims_rest:auth_uri(State, Scope),
	eims:send_edit(Pkt, iolist_to_binary(AuthUrl));
exec_cmd(#cmd{name = ?account, args = [<<"role">>, Role, Jid | _], context = #message{from=#jid{luser = User, lserver = Server}} = Pkt}=Cmd)
	when Role== <<"admin">> orelse Role== <<"user">> orelse Role== <<"none">> ->
	#jid{luser = U, lserver= S} = jid:from_string(Jid), %Nick = eims:string_to_lower(Jid(), %SysName = eims:string_to_lower(Nick),
	case eims:get_permission_level({User, Server}, [<<"admin">>]) of
		true -> case eims:get_storage_by_field({U, S}) of
							#eims_storage{} = UStor when Role == <<"none">> ->
								%% To change permission to the minimum when user cannot use JAMBoard
								ok = mnesia:dirty_write(UStor#eims_storage{jid = {U, S}, roles = [Role]}),
								eims:send_edit(Pkt, <<"Role ", Role/binary," has been added">>);
							#eims_storage{roles = Roles} = UStor ->
								ok = mnesia:dirty_write(UStor#eims_storage{jid = {U, S}, roles = [Role]}),
								eims:send_edit(Pkt, <<"Role ", Role/binary," has been added">>);
							_ ->
								case eims:is_ejuser(U) of
									true ->
									 {_PrivateData, UStorage} = eims:gen_summary(U, U),
							 			ok = mnesia:dirty_write(UStorage#eims_storage{roles = [Role]}),
										eims:send_edit(Pkt, <<"Role ",Role/binary," has been added">>);
									_ -> eims:send_edit(Pkt, <<"You can not change role of users">>)%%				_ -> {_PrivateData, UStorage} = eims:gen_summary(U, U),
%%						ok = mnesia:dirty_write(UStorage)
								end
	 				end;
		false -> eims:send_edit(Pkt, <<"You can not change role of users">>)
	end;
exec_cmd(#cmd{name = ?user, args = [<<"set">>, Nick | _], context = #message{from=#jid{luser = U, lserver = S}} = Pkt}=Cmd) ->
	Jid = jid:make(U, S), SysName = eims:string_to_lower(Nick),
	case eims:get_storage_by_field(SysName, #eims_storage.system_name) of
		#eims_storage{jid = #jid{} = Jid} = UStor ->
			ok = mnesia:dirty_write(UStor#eims_storage{jid = {U, S}, nick = Nick}),
			exec_cmd(Cmd#cmd{args = [Nick]});
		#eims_storage{} ->
			?dbg("/~s : ~p", [?user, Nick]),
			eims:send_edit(Pkt, <<"Nick ", Nick/binary, " is reserved">>);
		_ -> Is_EjUser = eims:is_ejuser(U),
			case eims:get_storage_by_field({U, S}) of
				#eims_storage{} = UStor ->
					ok = mnesia:dirty_write(UStor#eims_storage{jid = {U, S}, nick = Nick, system_name = SysName});
				_ when not Is_EjUser -> eims:send_edit(Pkt, <<"You can change nick on Integrated service  only">>);
				_ -> {_PrivateData, UStorage} = eims:gen_summary(Nick, U),
					ok = mnesia:dirty_write(UStorage)
			end,
			exec_cmd(Cmd#cmd{args = [Nick]})
	end;
exec_cmd(#cmd{name = ?user, args = [NickJid], context = #message{
	to = #jid{luser = Room, lserver = RoomHost}} = Pkt}) ->
	Body =
		case eims:get_jid_by_priv_data(NickJid, {Room, RoomHost}) of
			#eims_storage{nick = Nick, jid = #jid{luser = User, lserver = Server} = PeerJid} = DStorage ->
				MapStorage = maps:from_list(lists:zip([atom_to_binary(F) || F <- record_info(fields, eims_storage)], tl(tuple_to_list(DStorage)))),
				MapData = MapStorage#{<<"jid">> => jid:encode(PeerJid), <<"nick">> => Nick},
				Ips =
					eims:binary_join(lists:uniq(lists:flatten(
						[case ejabberd_sm:get_user_ip(User, Server, Resource) of
							 {error, _} -> [];
							 {IP, _Port} -> list_to_binary(inet_parse:ntoa(inet:ipv4_mapped_ipv6_address(IP)))
						 end || {U, S, Resource} <- ejabberd_sm:dirty_get_sessions_list(), User == U, Server == S])), <<",">>),
				eims_format:reply_to_text(user, MapData#{<<"id">> => Ips}, []);
			{error, _} = Err -> ?dbg("/~s ~s: ~p", [?user, NickJid, Err]),
				<<"User ", NickJid/binary, " has not been found">>
		end,
	eims:send_edit(Pkt, Body);
exec_cmd(#cmd{name = ?iserv_sub, args = [Channel], data = #{access_token := Token},
	context = #message{from = #jid{luser = LUser, lserver = LHost}, to = #jid{luser = Room, lserver = RoomHost} = To} = Pkt}) ->
	spawn(
		fun() ->
			Label = eims:hash([LUser, Room]),
			Msg = eims_ws_client:msg(<<"private/subscribe">>,
				#{<<"access_token">> => Token,
					<<"label">> => Label,
					<<"channels">> => [Channel]},
				Id = erlang:phash2(Label)), %% set id as hash of the label
			CallbackFun =
				fun(MsgMap) ->
					SendFun = %% send to all online user clients
					fun(Txt, SubEls) ->
						[case jid:decode(Jid) of
							 #jid{luser = LUser, lserver = LHost} = JID ->
								 ejabberd_router:route(
									 #message{
										 type = groupchat,
										 from = jid:replace_resource(To, eims:bot_nick()), %% add bot nick to room resource
										 to = JID,
										 body = [#text{data = Txt}],
										 sub_els = SubEls});
							 _ -> ok
						 end || {Jid, _Nick, _} <- mod_muc_admin:get_room_occupants(Room, RoomHost)]
					end,
					case MsgMap of
						#{<<"id">> := Id2, <<"result">> := [Channel2]} when Id2 == Id, Channel2 == Channel ->
							eims:send_edit(Pkt, <<"You have successfully subscribed to the ", Channel2/binary, " channel">>);
						#{<<"id">> := Id2, <<"result">> := []} when Id2 == Id ->
							eims:send_edit(Pkt, <<Channel/binary, " channel does not exist">>);
						#{<<"params">> := #{<<"label">> := Label2, <<"channel">> := Channel2,
							<<"data">> := Data = #{<<"timestamp">> := Timestamp}}} when Label2 == Label ->
							{Text, Entities} = eims_format:reply_to_text(Channel2, Data#{<<"timestamp">> => eims:ts_to_datetime(Timestamp)}, []),
							SendFun(<<Channel2/binary, Text/binary>>, [eims:bot_tag(), #message_entities{items = Entities}]);
						#{<<"error">> := #{<<"message">> := ErrMsg, <<"data">> := #{<<"reason">> := Reason}}} ->
							SendFun(<<ErrMsg/binary, "\n", Reason/binary>>, [eims:bot_tag()]);
						_ ->
							?dbg("unexpected message ~p", [MsgMap]),
							ok
					end
				end,
			eims_ws_client:send(Msg, CallbackFun)
		end);
exec_cmd(#cmd{name = ?banned, args = [], context = #message{} = Pkt}) ->
	Banned = eims:binary_join([<<"banned users:">> |
		lists:flatten([J || J <- mod_adhoc_eims:banned_jids()])], <<"\n\t">>),
	eims:send_edit(Pkt, Banned);
exec_cmd(#cmd{name = ?post, args = [Rooms, Text],
	context = #message{from = #jid{} = From,
		to = #jid{luser = InfoRoom, lserver = InfoServer}} = Pkt}) ->
	RoomList = re:split(Rooms, "\\h*,\\h*"),
	Fun =
		fun Fun(EncRoom) ->
			case catch jid:decode(EncRoom) of
				#jid{luser = <<>>, lserver = Room, lresource = <<>>} ->
					Fun(<<Room/binary, "@", InfoServer/binary>>);
				#jid{luser = _Room, lserver = InfoServer} = To ->
					Packet = Pkt#message{id = <<>>, to = To},
					{_, Nick, _} = lists:keyfind(jid:encode(From), 1,
						mod_muc_admin:get_room_occupants(InfoRoom, InfoServer)),
					eims:room_route(Packet#message{body = [#text{data = Text}]}, Nick, true);
				_ ->
					eims:send_edit(Pkt, <<"Invalid groupchat name \"", EncRoom/binary, "\"">>)
			end
		end,
	[Fun(EncRoom) || EncRoom <- RoomList];
exec_cmd(#cmd{name = ?upd, args = [Cmd, del], context = #message{} = Pkt}) ->
	MsgText =
		case mnesia:dirty_read(eims_cmd, Cmd) of
			[] -> <<" command not found">>;
			_ ->
				mnesia:dirty_delete(eims_cmd, Cmd),
				<<" command successfully deleted">>
		end,
	eims:send_edit(Pkt, <<" /", Cmd/binary, MsgText/binary>>);
exec_cmd(#cmd{name = ?upd, args = [Name, <<"//", Out/binary>>]} = Cmd) ->
	exec_cmd(Cmd#cmd{name = ?upd, args = [Name, <<"/", Out/binary>>]});
exec_cmd(#cmd{name = ?upd, args = [Name, <<_/integer, _/binary>> = Out], context = #message{} = Pkt}) ->
	Cmd2 =
		case mnesia:dirty_read(eims_cmd, Name) of
			[] -> #eims_cmd{cmd = Name, out = Out, doc = <<>>, acl = moderator};
			[#eims_cmd{type = custom} = Cmd] -> Cmd#eims_cmd{out = Out, acl = moderator};
			[#eims_cmd{type = base} = Cmd] -> Cmd
		end,
	Text =
		case Cmd2 of
			#eims_cmd{type = custom} ->
				IsUpdate =
					case Out of
						<<"/", Alias/binary>> ->
							[CustomName | _] = eims:split(Alias, 2),
							lists:keymember(CustomName, #cmd.name, cmds());
						_ -> true
					end,
				case IsUpdate of
					true ->
						mnesia:dirty_write(Cmd2),
						<<" command successfully updated">>;
					_ -> <<" command cannot be updated. Custom command cannot include other custom command">>
				end;
			_ ->
				<<" is base command and cannot be updated">>
		end,
	eims:send_edit(Pkt, <<" /", Name/binary, Text/binary>>);
exec_cmd(#cmd{name = ?badwords, args = []} = Cmd) ->
	exec_cmd(Cmd#cmd{args = [<<"default">>]});
exec_cmd(#cmd{name = ?badwords, args = [Lang], context = #message{from = #jid{luser = User}} = Pkt}) ->
	case mod_http_eims_api:get_banword_file(Lang) of
		{error, file_not_found} ->
			eims:send_edit(Pkt, <<"Blacklist for \"", Lang/binary, "\" language not found">>);
		_ ->
			Time = integer_to_binary(mod_mam:make_id()),
			Hash = eims:gen_hash_base64([User, Lang, Time]),
			Query = uri_string:compose_query([{<<"lang">>, Lang}, {<<"t">>, Time}, {<<"user">>, User}, {<<"hash">>, Hash}]),
			eims:send_edit(Pkt, list_to_binary(eims_rest:blacklist_uri(Query)))
	end;
exec_cmd(#cmd{name = ?badwords, args = [Lang, <<_/integer, _/integer, _/integer, _/binary>> = BadWord],
	context = Pkt}) ->
	BlackLists = gen_mod:get_module_opt(global, mod_pottymouth, blacklists),
	case lists:keyfind(binary_to_atom(Lang), 1, BlackLists) of
		{AtomLang, BL} ->
			case file:read_file(FilePath = atom_to_list(BL)) of
				{ok, Binary} ->
					file:write_file(FilePath, <<Binary/binary, "\n", BadWord/binary>>),
					ok = banword_gen_server:reload(AtomLang),
					eims:send_edit(Pkt, <<"\"", BadWord/binary, "\" successfully added to word black list">>),
					ok;
				Err ->
					?dbg("invalid read file ~s", [FilePath]),
					eims:send_edit(Pkt, <<"interlnal error">>), Err
			end;
		false ->
			eims:send_edit(Pkt, <<Lang/binary, " blacklist not found">>)
	end;
exec_cmd(#cmd{name = ?badwords, args = [_Lang, _BadWord], context = Pkt}) ->
	eims:send_edit(Pkt, <<"bad word must have at least 3 characters">>);
exec_cmd(#cmd{name = ?muc, args = [<<"del">>, Room], context = #message{to = #jid{luser = R, server = Server}} = Pkt}) ->
	Res = case catch mod_muc_admin:destroy_room(Room, Server) of
		       ok ->
			       eims_db:remove_from_archive_with_bare_peer(jid:make(Room, Server)),
			       {ok, <<"Room ", Room/binary, "@", Server/binary, " successfully deleted">>};
		       {error, _Reason} = Err -> Err;
		       {'EXIT', _} -> <<"Internal error">>
	       end,
	case {R, Res} of
		{<<>>, {ok, Text}} -> ok;
		{<<>>, {error, Text}} -> ?err("del room: ~s", [Text]);
		{_, {_, T}} -> eims:send_edit(Pkt, T)
	end;
exec_cmd(#cmd{name = ?muc, args = [<<"rfq.", _/binary>> = Room, Title],
			  context = #message{from = #jid{luser = User, lserver = Host}} = Pkt}) ->
	Service = eims:muc_host(),
	ComponentJid = eims:bot_component(),
	BotNick = eims:bot_nick(),
	Affiliations = [{{User, Host, <<>>}, {owner, <<>>}}, {{<<>>, ComponentJid, <<>>}, {admin, <<>>}}],
	Subscribers = [{jid:make(ComponentJid), BotNick, [?NS_MUCSUB_NODES_MESSAGES]}],
	Opts = maps:from_list(mod_muc_opt:default_room_options(Host)),
	%% TODO sometimes the subscription doesn't work so here you need to use something more reliable
	case mod_muc:create_room(Service, erlang:list_to_binary(str:to_lower(binary_to_list(Room))),
		maps:to_list(Opts#{public := false, members_only => true,	title => Title,
			affiliations => Affiliations, subscribers => Subscribers})) of
			ok              -> eims:send_edit(Pkt, <<"Room ", Room/binary, "@", Service/binary, " successfully created">>);
			{error, Reason} -> eims:send_edit(Pkt, list_to_binary(Reason));
			{'EXIT', _}     -> eims:send_edit(Pkt, <<"Internal error">>)
	end;
exec_cmd(#cmd{name = ?muc, args = [Public, Title], context = #message{from = #jid{luser = User, lserver = Host}, to = #jid{lserver = Server}} = Pkt})
	when Public == <<"pub">>; Public == <<"priv">> ->
	IsPublic = case Public of <<"pub">> -> <<"true">>; _ -> <<"false">> end,
	EscTitle = list_to_binary(edoc_lib:escape_uri(binary_to_list(Title))), %% escape title
	Title2 = re:replace(EscTitle, "%20", "_", [global]), %% in escaped title replace "%20" (space) to "_"
	Title3 = re:replace(Title2, "%\\d\\d|%\\d[a-f]|%[a-f][a-f]|%[a-f]\\d", "", [global]), %% remove all escaped symbols
	Fix =
		fun Fix([H | T]) -> [H | Fix(T)];
			Fix(T) -> [T]
		end,
	R = str:to_lower(eims:binary_join(lists:flatten(Fix(Title3)), <<>>)), %% fix possible improper list after previous replace
	R2 = re:replace(R, "\\s+", " ", [global]), %% replace multispaces
	R3 = binary:part(R2, {0, min(byte_size(R2), 220)}),
	Room =
		case lists:keyfind(R3, 1, mod_muc:get_online_rooms(Server)) of
			false when R3 /= <<>> -> R3;
			_ -> <<R3/binary, "_", (integer_to_binary(mod_mam:make_id()))/binary>>
		end,
	case catch mod_muc_admin:create_room_with_opts(Room, Server, eims:host(), [{<<"public">>, IsPublic}, {<<"title">>, Title}]) of
		ok ->
			catch mod_muc_admin:set_room_affiliation(Room, Server, <<User/binary, "@", Host/binary>>, <<"owner">>),
			eims:send_edit(Pkt, <<"Room ", Room/binary, "@", Server/binary, " successfully created">>);
		{error, Reason} -> eims:send_edit(Pkt, list_to_binary(Reason));
		{'EXIT', _} -> eims:send_edit(Pkt, <<"Internal error">>)
	end;

exec_cmd(#cmd{room_access = #{rfq := Module}} = Cmd) ->
	Module:exec_cmd(Cmd);
exec_cmd(#cmd{name = Name, custom = false} = Cmd) ->
	exec_cmd(
		case lists:keymember(Name, #cmd.name, cmds()) of
			true -> {error, invalid_params, Cmd};
			_ -> {error, invalid_cmd, Cmd}
		end);
exec_cmd(#cmd{} = Cmd) ->
	Cmd;
exec_cmd(Err) ->
	?dbg("ERROR: exec_cmd: ~p", [Err]),
	Err.

%% ACLs
acl(#cmd{acl = admin, data = #cmd{} = CmdOrig,
	context = #message{from = #jid{luser = User, lserver = Host}} = _Pkt}) ->
	case acl:match_rule(Host, eims_admin, #{usr => {User, Host, <<>>}}) of
		allow -> CmdOrig; deny -> {error, access_denied} end;
acl(#cmd{context = #message{} = Pkt, data = #cmd{data = #{} = Data} = CmdOrig} = Cmd) when not is_map_key(sender_pkt, Data) ->
	acl(Cmd#cmd{data = CmdOrig#cmd{data = Data#{sender_pkt => Pkt}}});
acl(#cmd{data = #cmd{context = #message{from = From} = Pkt, data = #{access_token := true, sender_pkt := SenderPkt} = Data} = CmdOrig} = Cmd) ->
	case eims_rest:get_access_token(From) of
		{error, _} when SenderPkt /= Pkt -> {error, "Party token not found"};
		{error, _}                       -> {error, "Token not found"};
		Token                            -> acl(Cmd#cmd{data = CmdOrig#cmd{data = Data#{access_token := Token}}})
	end;
acl(#cmd{args = [help | _], data = #cmd{context = #message{to = #jid{luser = <<"rfq.", _/binary>>}}, room_access = RoomAccess}})
	when not is_map_key(rfq, RoomAccess) ->
	{error, access_denied};
acl(#cmd{data = #cmd{context = #message{to = #jid{luser = <<"rfq.", _/binary>>}}, room_access = #{rfq := true} = RoomAccess} = CmdOrig} = Cmd) ->
	acl(Cmd#cmd{data = CmdOrig#cmd{room_access = RoomAccess#{rfq => mdrfq_umarket}}});

acl(#cmd{name = ?muc, data = #cmd{} = CmdOrig, %% ACL for "\muc" command because the room deleting from menu is needs to send #message{from = #jid{user = <<>>, server = Host}}
	context = #message{from = #jid{luser = User, lserver = Host}} = _Pkt}) ->
	case acl:match_rule(Host, eims_admin, #{usr => {User, Host, <<>>}}) of
		allow -> CmdOrig;
		deny ->
			case acl:match_rule(Host, configure, #{usr => {User, Host, <<>>}}) of
				allow -> CmdOrig; deny -> {error, access_denied}
			end
	end;
acl(#cmd{acl = moderator, args = [], data = #cmd{} = CmdOrig,
			context = #message{from = #jid{luser = User}, to = #jid{luser = Room, lserver = RoomHost}} = _Pkt}) ->
	case catch mod_muc_admin:get_room_affiliations(Room, RoomHost) of
		Affs when is_list(Affs) ->
			case lists:keyfind(User, 1, Affs) of
				{_, _, A, _} = Aff when A == admin; A == owner -> CmdOrig#cmd{data = {Affs, Aff}};
				_ -> {error, access_denied}
			end;
		E -> ?DEBUG("ERROR: ~p", [E]),
			{error, access_denied}
	end;
acl(#cmd{acl = moderator, args = [PeerNick|_], data = #cmd{} = CmdOrig} = Cmd) ->
	case acl(Cmd#cmd{data = Cmd, args = []}) of
		#cmd{data = {Affs, Aff}} ->
			case lists:keyfind(PeerNick, 1, Affs) of
				Aff -> CmdOrig#cmd{data = self};
				{_, _, A, _} = Aff when A == admin; A == owner -> {error, access_denied};
				_ -> CmdOrig
			end;
		{error, _} = Err -> Err
	end;
acl(#cmd{data = #cmd{room_access = #{rfq := true}}}) ->
	{error, access_denied};
acl(#cmd{data = #cmd{room_access = #{rfq := Module}}} = Cmd) ->
	Module:acl(Cmd);
acl(#cmd{acl = all, data = #cmd{} = CmdOrig} = Cmd) ->
	CmdOrig;
acl(#cmd{name = Name, args = [_PeerNick|_], data = [], broadcast = false} = Cmd)
	when Name == ?rban; Name == ?runban; Name == ?kick; Name == ?admin->
	case acl(Cmd#cmd{name = [], data = Cmd}) of
		#cmd{data = self}   -> {error, access_denied};
		#cmd{}              -> Cmd;
		Err                 -> Err
	end;
acl(#cmd{name = ?help, context = #message{}, data = [], broadcast = false} = Cmd) ->
	Acl = case acl(Cmd#cmd{data = Cmd, acl = admin}) of
		      #cmd{} -> admin;
		      _ -> case acl(Cmd#cmd{name = ?runban, args = [<<"all">>], acl = moderator}) of
			           #cmd{} -> moderator;
			           _ -> all
		           end
	      end,
	Cmd#cmd{data = Acl};
acl(#cmd{name = ?iserv_auth, data = [], context = #message{from = #jid{luser = <<"whale.", _/binary>>}} = Pkt, broadcast = false} = _Cmd) ->
	eims:send_edit(Pkt, <<"You do not have access to /iserv_auth command">>),
	{error, access_denied};
acl(#cmd{name = Name, data = Data, context = Pkt, custom = Custom} = Cmd) when not is_record(Data, cmd) ->
	case acl(Cmd#cmd{data = Cmd}) of
		{error, _} = Err -> Err;
		{error, _, _} = Err -> Err;
		#cmd{} = Cmd2 ->
			case mnesia:dirty_read(eims_cmd, Name) of
				[#eims_cmd{type = custom, out = NewCmd}] when not Custom ->
					Cmd2#cmd{context = Pkt#message{body = [#text{data = NewCmd}]}, custom = true};
				[#eims_cmd{type = custom}] ->
					{error, custom_alias};
				[#eims_cmd{type = base}]->
					Cmd2;
				_ -> {error, invalid_cmd, Cmd}
			end
	end;
acl({error, _} = Err) ->
	?dbg("ERROR: acl: ~p", [Err]),
	Err;
acl(Cmd) ->
	?dbg("ERROR: acl: invalid command: ~p", [Cmd]),
	{error, invalid_cmd, Cmd}.

send_sys_msg(Cmd) ->
	send_sys_msg(Cmd, []).
send_sys_msg(Cmd, bot) ->
	send_sys_msg(Cmd, [eims:bot_tag()]);
send_sys_msg(#cmd{data = Text, broadcast = false, context = Pkt}, SubEls) ->
	eims:send_edit(Pkt, Text, SubEls);
send_sys_msg(#cmd{} = Cmd, SubEls) ->
	send_sys_msg(Cmd, SubEls, true).
send_sys_msg(#cmd{data = Text, context = #message{from = #jid{lserver = Host} = From,
	to = #jid{luser = Room, lserver = RoomHost}, sub_els = SubEls} = Pkt}, SubEls2, Store) ->
	case lists:keyfind(jid:encode(From), 1, mod_muc_admin:get_room_occupants(Room, RoomHost)) of
		{_, Nick, _} ->
			FromHeader = <<"from ", Nick/binary>>, %% TODO add entity for system
			SubEls3 = eims_format:offset(byte_size(FromHeader) + 1, SubEls2),
			eims:room_route(Pkt#message{from = jid:make(<<"system">>, Host),
				body = [#text{data = <<FromHeader/binary, "\n", Text/binary>>}], sub_els = SubEls}, eims:bot_nick(), Store, SubEls3);
		_ -> {error, nick_not_found}
	end.

%% TODO help reset commands. Remove in future
hard_save_cmds() -> %% rewrite commands by default
	[mnesia:dirty_write(#eims_cmd{cmd = Name, broadcast = Broadcast, acl = Acl, type = base, doc = Doc}) ||
		#cmd{name = Name, broadcast = Broadcast, acl = Acl, doc = Doc} <- cmds() ++ mdrfq_umarket:cmd()].
save_cmds() -> %% save new commands
	[case mnesia:dirty_read(eims_cmd, Name) of
		 [] ->
		    mnesia:dirty_write(#eims_cmd{cmd = Name, broadcast = Broadcast, acl = Acl, type = base, doc = Doc}),
		    ?dbg("~s command seccessfully added", [Name]);
		 _ -> ?dbg("~s command skipped", [Name])
	 end || #cmd{name = Name, broadcast = Broadcast, acl = Acl, doc = Doc} <- cmds() ++ mdrfq_umarket:cmd()].
filter_base_cmds() -> %% remove renamed commands from db
	[case mnesia:dirty_read(eims_cmd, Key) of
		 [#eims_cmd{cmd = Name, type = base}] ->
			 case lists:keyfind(Name, #cmd.name, cmds() ++ mdrfq_umarket:cmd()) of
				 #cmd{} -> ok;
				 false -> mnesia:dirty_delete(eims_cmd, Name),
					 binary_to_list(Name) ++ " command removed from db"
			 end;
		 _ -> ok
	 end || Key <- mnesia:dirty_all_keys(eims_cmd)].
reset_custom_cmds() ->
	[case mnesia:dirty_read(eims_cmd, Key) of
		 [#eims_cmd{type = undefined} = Cmd] -> mnesia:dirty_write(Cmd#eims_cmd{type = custom, acl = moderator, broadcast = false});
		 _ -> ok
	 end || Key <- mnesia:dirty_all_keys(eims_cmd)].

-module(admin_eims_SUITE).
-compile(export_all).

-include_lib("escalus/include/escalus.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").
-include_lib("exml/include/exml.hrl").
-include_lib("xmpp/include/xmpp_codec.hrl").
-include_lib("xmpp/include/ns.hrl").
-include_lib("ejabberd/include/mod_mam.hrl").
-include("../include/eims.hrl").

-import(eims, [wait_for_result/2, wait_for_result/4, wait_for_list/1, wait_for_list/2, wait_for_stanzas/2,
					wait_for_stanzas/3, wait_for_stanza/1, wait_for_stanza/2, send/2]).
-import(ct_helper, [config/2, doc/1]).

-define(a(Condition), ?assert(Condition)).
-define(b(Cmd), Cmd/binary).

-type(xmlel() :: #xmlel{}).
-type(ljid() :: {binary(), binary(), binary()}).

%% API

%%--------------------------------------------------------------------
%% Suite configuration
%%--------------------------------------------------------------------

all() ->
	[{group, main}].

groups() ->
	MainSequence = ct_helper:all(?MODULE),
	[{main, [sequence], MainSequence}, {local, [sequence], MainSequence -- [eims_badwords_story]}].

init_per_suite(Config) ->
	[escalus:Fun([{escalus_user_db, {module, escalus_ejabberd}} | Config], escalus_users:get_users([alice, david])) || Fun <- [delete_users, create_users]],
	[begin
		 OldV = application:get_env(ejabberd, K, V),
		 application:set_env(ejabberd, K, ?MODULE),
		 {K, OldV}
	 end || {K, V} <- do_env_vars()] ++ Config.

end_per_suite(Config) ->
%%	escalus:delete_users([{escalus_user_db, {module, escalus_ejabberd}} | Config], escalus_users:get_users([alice])),
	[application:set_env(ejabberd, Key, proplists:get_value(Key, Config, Val)) || {Key, Val} <- do_env_vars()],
	Config.

init_per_group(_GroupName, Config) ->
	Config.

end_per_group(_GroupName, Config) ->
	Config.


init_per_testcase(format_story, Config) ->
	escalus:init_per_testcase(format_story, Config);
init_per_testcase(flood_story, Config) ->
	application:set_env(ejabberd, flood_story, true),
	init_per_testcase(admin_eims_story, [{min_message_interval, 1} | Config]);
init_per_testcase(eims_upload_story, Config) ->
	do_create_upload_file(),
	init_per_testcase(admin_eims_story, Config);
init_per_testcase(p2p_offline_story, Config) ->
	init_per_testcase(p2p_story, Config);
init_per_testcase(p2p_story, Config) ->
	UserNodes = [escalus_config:get_ct({escalus_users, U, username}) || U <- [bob, clara, alice, david]],
	[Server | _] = ejabberd_option:hosts(),
	[mod_mam:remove_mam_for_user(UserNode, Server) || UserNode <- UserNodes],
	[eims_offline:remove_offline_msgs_by_tags([#origin_id{id = OriginId}, #replace{id = OriginId}])
		|| OriginId <- [<<"1">>, <<"2">>, <<"3">>, <<"retract_1">>]],
	init_per_testcase(admin_eims_story, Config);
init_per_testcase(muc_manipulation_story, Config) ->
	Server = mod_muc_opt:host(hd(ejabberd_option:hosts())),
	MUCTmp = <<"tmp_muc">>, MUCTitleTmp = <<"tmp muc">>,
	catch mod_muc_admin:destroy_room(MUCTmp, Server),
	init_per_testcase(admin_eims_story, [{muc, MUCTmp}, {muc_title, MUCTitleTmp} | Config]);
init_per_testcase(eims_token_story, Config) ->
	Intervals = [{K, application:get_env(ejabberd, K, V)} || {K, V} <-
		[{refresh_token_interval, 800}, {access_token_interval, 90}]],
	application:set_env(ejabberd, refresh_token_interval, 2),
	application:set_env(ejabberd, access_token_interval, 1),
	init_per_testcase(admin_eims_story, Intervals ++ Config);
init_per_testcase(pubsub_story, Config) ->
	init_per_testcase(p2p_offline_story, Config);
init_per_testcase(CaseName, Config) ->
	Config2 = escalus:init_per_testcase(CaseName, Config),
	meck:new(eims, [no_link, passthrough, unstick]),
	meck:expect(mod_muc_opt, min_message_interval, fun (_) -> proplists:get_value(min_message_interval, Config2, 0) end),
	[Host, RoomHost, Rooms, Users] =
		[escalus_ct:get_config(K) || K <- [ejabberd_domain, room_host, eims_rooms, escalus_users]],
	[begin
		 Node = config(username, UserData),
		 Server = config(server, UserData),
		 mnesia:dirty_delete(eims_storage, {Node, Server})
	 end || {_, UserData} <- Users],
	[begin
		 [Room, RoomOpts, Affs] = [config(K, Opts) || K <- [name, options, affiliations]],
		 catch mod_muc_admin:destroy_room(Room, RoomHost),
		 ok = wait_for_result(fun() -> catch mod_muc_admin:create_room_with_opts(Room, RoomHost, Host, RoomOpts) end, ok), %% TODO add affiliations in room options
		 [begin
			  UserCfg = config(U, Users),
			  Jid = jid:to_string(list_to_tuple([config(K, UserCfg) || K <- [username, server]] ++ [<<>>])),
			  ok = mod_muc_admin:set_room_affiliation(Room, RoomHost, Jid, atom_to_binary(Aff))
		  end || {U, Aff} <- Affs]
	 end || {_, Opts} <- Rooms],
	case proplists:get_value(drop_token, Config, true) of
		true -> [eims:drop_tokens(jid:decode(escalus_users:get_jid(Config, User))) || {User, _} <- Users];
		_ -> ok
	end,
	meck:new(httpc, [no_link, passthrough, unstick]),
	meck:new(acl, [no_link, passthrough]),
	meck:expect(httpc, request, fun do_request/4),
	meck:expect(acl, match_rule, fun do_match_rule/3),
	Config2.

end_per_testcase(format_story, Config) ->
	escalus:end_per_testcase(format_story, Config);
end_per_testcase(flood_story, Config) ->
	application:set_env(ejabberd, flood_story, false),
	end_per_testcase(admin_eims_story, Config);
end_per_testcase(eims_upload_story, Config) ->
	Host = hd(ejabberd_option:hosts()),
	UploadDir = binary_to_list(mod_http_upload_opt:docroot(Host)),
	file:del_dir_r(filename:join(UploadDir, "alice")),
	end_per_testcase(admin_eims_story, Config);
end_per_testcase(eims_custom_story, Config) ->
	[mnesia:dirty_delete(eims_cmd, Cmd) || Cmd <- [<<"test_text">>, <<"test_custom">>]],
	end_per_testcase(admin_eims_story, Config);
end_per_testcase(eims_token_story, Config) ->
	[application:set_env(ejabberd, K, config(K, Config))
		|| K <- [refresh_token_interval, access_token_interval]],
	application:set_env(ejabberd, refresh_token_http_code, 200),
	end_per_testcase(admin_eims_story, Config);
end_per_testcase(CaseName, Config) ->
	meck:unload(),
	escalus:end_per_testcase(CaseName, Config).

%%--------------------------------------------------------------------
%% admin EIMS tests
%%--------------------------------------------------------------------

admin_eims_story(Config) ->
	RoomJid = do_test_room_jid(),
	[AliceNick, BobNick, _ClaraNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob, clara]],
	_WhaleNodes = [BobNode, ClaraNode] = [escalus_config:get_ct({escalus_users, U, username}) || U <- [bob, clara]],
	_WhalePwds = [_BobPwd, _ClaraPwd] = [escalus_config:get_ct({escalus_users, U, password}) || U <- [bob, clara]],
	[Room, RoomHost] = binary:split(RoomJid, <<"@">>),
	Host = escalus_config:get_ct(ejabberd_domain),
	escalus:story(Config, [{alice, 1}, {bob, 1}, {clara, 1}],
		fun(#client{jid = AliceJid} = Alice,
			#client{jid = BobJid} = Bob,
			#client{jid = ClaraJid} = _Clara) ->
			Jids = [AliceJid, BobJid],
			[_AliceNode, BobNode, ClaraNode] = Nodes = [hd(binary:split(J, <<"@">>)) || J <- [AliceJid, BobJid, ClaraJid]],
			[[_], [], []] = [mnesia:dirty_read(passwd, {Node, Host}) || Node <- Nodes],
			%% Alice has no token and Bob has token
			[{error, token_not_found}, BobNode] = [eims_rest:get_access_token(jid:decode(Jid)) || Jid <- Jids],

			%% Alice enter to ChatRoom
			do_enter_room(Alice, RoomJid, AliceNick),
			%% Alice sends a message to ChatRoom
			escalus:wait_for_stanza(Alice), %% Alice wait for presence from ChatRoom
			send(Alice, HelloPkt = escalus_stanza:groupchat_to(RoomJid, <<"HELLO ALL!">>)),

			%% Alice gets the message from ChatRoom
			escalus:assert(is_groupchat_message, [<<"HELLO ALL!">>], escalus:wait_for_stanza(Alice)),

			HackerPkt = xmpp:set_subtag(xmpp:decode(HelloPkt), #bot{hash = <<"hacker_hash">>}), %% hacker message with bot subtag
			send(Alice, HackerPkt), %% Alice sends hacker message
			#message{body = [#text{data = <<"Message forbidden">>}]} = xmpp:decode(escalus:wait_for_stanza(Alice)),

			%% Bob enter to ChatRoom
			do_enter_room(Bob, RoomJid, BobNick),
			%% Bob sends a message to ChatRoom
			[_, _] = wait_for_list(fun() -> mod_muc_admin:get_room_occupants(Room, RoomHost) end, 2),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"HELLO!">>)),
			escalus_client:wait_for_stanzas(Bob, 3), %% Bob wait for 3 presence from ChatRoom

			%% Bob gets the message from ChatRoom
			escalus:assert(is_groupchat_message, [<<"HELLO!">>], escalus:wait_for_stanza(Bob)),
			escalus_client:wait_for_stanzas(Alice, 1), %% Bob wait for 3 presence from ChatRoom
			escalus:assert(is_groupchat_message, [<<"HELLO!">>], escalus:wait_for_stanza(Alice)),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"TEST">>)),
			{_, NewBobNick, _} = lists:keyfind(BobJid, 1, mod_muc_admin:get_room_occupants(Room, RoomHost)), %% get "whale" nick
			%% Bob and Alice gets the message TEST from ChatRoom
			Clients = [Bob, Alice],
			[escalus:assert(is_groupchat_message, [<<"TEST">>], escalus:wait_for_stanza(Client)) || Client <- Clients],

			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?user), " alice">>)), %% access denied for Bob
			escalus:assert(is_groupchat_message, [<<"ERROR: Access denied">>], escalus:wait_for_stanza(Bob)),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/invalid_cmd">>)),
			[#xmlel{} = InvalidMsg] = escalus:wait_for_stanzas(Alice, 1),
			#message{body = [#text{data = <<"Invalid /invalid_cmd command">>}]} = xmpp:decode(InvalidMsg),

			%% get Bob data if Bob in room
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?user), " ", NewBobNick/binary>>)),
			[#xmlel{} = UserMsg] = escalus:wait_for_stanzas(Alice, 1),
			#message{body = [#text{data = <<"\t", _/binary>> = UserData}]} = xmpp:decode(UserMsg),

			%% get Bob data if Bob is out of the room
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?kick), " fakenick">>)),
			escalus:assert(is_groupchat_message, [<<"User \"fakenick\" not found in this groupchat">>], escalus:wait_for_stanza(Alice)),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?kick), " ", NewBobNick/binary>>)),
			escalus:assert(is_presence_with_type, [<<"unavailable">>], escalus:wait_for_stanza(Alice)),
			[{_, AliceNick, _}] = wait_for_list(fun() -> mod_muc_admin:get_room_occupants(Room, RoomHost) end, 1),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?user), " ", NewBobNick/binary>>)),

			[_, #xmlel{name = <<"message">>} = UserMsg2] = escalus:wait_for_stanzas(Alice, 2),
			#message{body = [#text{data = <<"\t", _/binary>> = UserData}]} = xmpp:decode(UserMsg2),
			do_enter_room(Bob, RoomJid, <<"bob">>),
			escalus_client:wait_for_stanzas(Bob, 7),
			escalus_client:wait_for_stanzas(Alice, 1),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?purge), " ", NewBobNick/binary>>)),
			[[_, _] = escalus:wait_for_stanzas(Client, 2) || Client <- Clients], %% 2 retract messages
			PurgeSuccessMsg = <<NewBobNick/binary, " messages have been deleted successfully">>,
			escalus:assert(is_groupchat_message, [PurgeSuccessMsg], escalus:wait_for_stanza(Alice)),

			[_] = wait_for_list(fun() -> eims:select_history({Room, RoomHost}) end, 1),
			[_] = wait_for_list(fun() -> eims_db:read_archive(Room, RoomHost) end, 1),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"PURGE TEST BY JID">>)),
			{_, NewBobNick, _} = lists:keyfind(BobJid, 1, mod_muc_admin:get_room_occupants(Room, RoomHost)), %% get "whale" nick
			%% Bob and Alice gets the message "PURGE TEST" from ChatRoom
			[escalus:assert(is_groupchat_message, [<<"PURGE TEST BY JID">>], escalus:wait_for_stanza(Client)) || Client <- Clients],
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?purge), " ", BobJid/binary>>)), %% purge by nick
			[escalus:wait_for_stanzas(Client, 1) || Client <- Clients], %% 1 retract messages
			PurgeSuccessMsg2 = <<BobJid/binary, " messages have been deleted successfully">>,
			escalus:assert(is_groupchat_message, [PurgeSuccessMsg2], escalus:wait_for_stanza(Alice)),
			[_] = wait_for_list(fun() -> eims_db:read_archive(Room, RoomHost) end, 1),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?purge), " all">>)),
			[escalus:wait_for_stanzas(Client, 1) || Client <- [Bob, Alice]], %% 1 retract messages
			PurgeAllSuccessMsg = <<"all messages have been deleted successfully">>,
			escalus:assert(is_groupchat_message, [PurgeAllSuccessMsg], escalus:wait_for_stanza(Alice)),
			[] = wait_for_list(fun() -> eims_db:read_archive(Room, RoomHost) end),
			[] = wait_for_list(fun() -> eims:select_history({Room, RoomHost}) end),


			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"delete message by id!">>)),
			W = #xmlel{name = <<"message">>, children = [#xmlel{attrs = [_, {<<"id">>, Id} | _]} | _]} %% get id from history
				= escalus:wait_for_stanza(Bob),
			escalus:assert(is_groupchat_message, [<<"delete message by id!">>], W),
			escalus:wait_for_stanzas(Alice, 1),

			IntId = binary_to_integer(Id),
			[#message{meta = #{stanza_id := IntId}, body = [#text{data = <<"delete message by id!">>}]}] =
				eims:select_history({Room, RoomHost}),
			eims:edit_history_msg(Room, RoomHost, Host, binary_to_integer(Id), EditText = <<"edit message by id!">>),

			[#message{meta = #{stanza_id := IntId}, body = [#text{data = <<"edit message by id!">>}]}] =
				eims:select_history({Room, RoomHost}),

			#archive_msg{packet = EditMsg} = eims_db:edit_mam_msg_by_id({Room, RoomHost}, Id, EditText),
			#message{body = [#text{data = EditText}]} = xmpp:decode(EditMsg),
			#archive_msg{packet = GetMsg} =
				wait_for_result(fun() -> eims_db:get_mam_msg_by_id({Room, RoomHost}, Id) end, fun(#archive_msg{}) -> true; (_) -> false end),
			EditMsg = #message{body = [#text{data = _Text}]} = xmpp:decode(GetMsg),

			NewEditTxt = <<"new edit message text">>,
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?edit), " ", NewEditTxt/binary>>)),
			#archive_msg{} = eims_db:get_last_msg({Room, RoomHost}, NewBobNick),
			EditMsgs = [escalus:wait_for_stanza(Client) || Client <- Clients],
			[true = xmpp:has_subtag(xmpp:decode(ReplaceMsg), Tag) || Tag <- [#chatstate{type = active}, #replace{}, #origin_id{}], ReplaceMsg <- EditMsgs],
			#origin_id{id = _OriginId} = xmpp:get_subtag(xmpp:decode(hd(EditMsgs)), #origin_id{}),

			[#message{meta = #{stanza_id := IntId}, body = [#text{data = NewEditTxt}]}] =
				eims:select_history({Room, RoomHost}),

			#archive_msg{packet = NewEditPkt} = eims_db:get_mam_msg_by_id({Room, RoomHost}, Id),
			#message{body = [#text{data = NewEditTxt}]} = xmpp:decode(NewEditPkt),

			%% remove manually messages from archive and history
			eims:delete_from_history_by_id(Room, RoomHost, Host, [binary_to_integer(Id)]),
			eims_db:remove_mam_msg_by_ids(Room, RoomHost, [Id]),
			[] = wait_for_list(fun() -> eims_db:read_archive(Room, RoomHost) end),
			[] = wait_for_list(fun() -> eims:select_history({Room, RoomHost}) end),

			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"lastmsg del test">>)),
			escalus:assert(is_groupchat_message, [<<"lastmsg del test">>], escalus:wait_for_stanza(Bob)),
			escalus:wait_for_stanzas(Alice, 1),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?del)>>)),
			ApplyMsgs = [escalus:wait_for_stanza(Client) || Client <- Clients],
			[true = xmpp:has_subtag(xmpp:decode(ApplyMsg), Tag) || Tag <- [#fasten_apply_to{}, #hint{type = store}], ApplyMsg <- ApplyMsgs],
			[] = wait_for_list(fun() -> eims:select_history({Room, RoomHost}) end),
			[] = wait_for_list(fun() -> eims_db:read_archive(Room, RoomHost) end),

			[#eims_cmd{stats = HelpStats}] = mnesia:dirty_read(eims_cmd, ?help),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?help)>>)),
			HelpPkt = #message{body = [#text{data = <<"help triggered", _/binary>>}]} = xmpp:decode(escalus:wait_for_stanza(Bob)),
			HelpStats2 = HelpStats + 1,
			[#eims_cmd{stats = HelpStats2}] = mnesia:dirty_read(eims_cmd, ?help),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?stats)>>)),
			#message{body = [#text{data = <<"Command stats for whale. users:", _/binary>>}]} = xmpp:decode(escalus:wait_for_stanza(Alice)),
			ok
		end).

eims_ban_story(Config) ->
	RoomJid = do_test_room_jid(),
	[AliceNick, BobNick, _ClaraNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob, clara]],
	WhaleNodes = [BobNode, ClaraNode] = [escalus_config:get_ct({escalus_users, U, username}) || U <- [bob, clara]],
	WhalePwds = [_BobPwd, _ClaraPwd] = [escalus_config:get_ct({escalus_users, U, password}) || U <- [bob, clara]],
	[Room, RoomHost] = binary:split(RoomJid, <<"@">>),
	Host = escalus_config:get_ct(ejabberd_domain),
	escalus:story(Config, [{alice, 1}, {bob, 1}, {clara, 1}],
		fun(#client{jid = AliceJid} = Alice,
			#client{jid = BobJid} = Bob,
			#client{jid = ClaraJid} = _Clara) ->
			[_AliceNode, BobNode, ClaraNode] = Nodes = [hd(binary:split(J, <<"@">>)) || J <- [AliceJid, BobJid, ClaraJid]],
			[[_], [], []] = [mnesia:dirty_read(passwd, {Node, Host}) || Node <- Nodes],
			do_enter_room(Bob, RoomJid, BobNick),
			do_enter_room(Alice, RoomJid, AliceNick),
			[escalus:wait_for_stanzas(C, 2) || C <- [Alice, Bob]],

			{_, NewBobNick, _} = lists:keyfind(BobJid, 1, mod_muc_admin:get_room_occupants(Room, RoomHost)), %% get "whale" nick
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/ban ", ClaraJid/binary>>)),
			[ClaraBanMsg] = escalus:wait_for_stanzas(Alice, 1),
			#message{body = [#text{data = <<"banned accounts:\n\tsub-account whale.clara@localhost">>}]} = xmpp:decode(ClaraBanMsg),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/ban ", NewBobNick/binary>>)),
			_LBan = [BobBanMsg, UnavailablePresence] =
				lists:sort(escalus:wait_for_stanzas(Alice, 2)),

%%			BanMsg = <<NewBobNick/binary, " has been banned">>,
			%#message{body = [#text{data = <<"main account", _/binary>>}]} = xmpp:decode(BobBanMsg),
			#message{body = [#text{data = <<"banned accounts:\n\tmain account whale.bob@localhost\n\tsub-account whale.clara@localhost">>}]}
				= xmpp:decode(BobBanMsg),
			%#message{body = [#text{data = <<"main account", _/binary>>}]} = xmpp:decode(BobNickBanMsg),
			#presence{type = unavailable} = xmpp:decode(UnavailablePresence),
			ClaraJID = <<ClaraNode/binary, "@", Host/binary>>,

			[#eims_storage{id = 8888, access = deny}] = mnesia:dirty_read(eims_storage, {ClaraNode, Host}),
			[#eims_storage{access = deny}] = mnesia:dirty_read(eims_storage, {BobNode, Host}),

			BobJ = jid:decode(BobJID = <<BobNode/binary, "@", Host/binary>>),
			true = wait_for_result(fun() -> mod_adhoc_eims:is_banned(BobJ) end, true),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?banned)>>)),
			[BannedMsg] = escalus:wait_for_stanzas(Alice, 1),
			#message{body = [#text{data = <<"banned users:\n\twhale.clara@localhost\n\twhale.bob`s main account">>}]} = xmpp:decode(BannedMsg),
			[begin
				 send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?unban), " ", J/binary>>)),
				 escalus:assert(is_groupchat_message, [<<J/binary, " has been unbanned">>], escalus:wait_for_stanza(Alice)),
				 false = mod_adhoc_eims:is_banned(BobJ)
			 end || J <- [BobJID, ClaraJID]],

			[#eims_storage{id = BobId, access = allow}] = wait_for_list(fun() -> mnesia:dirty_read(eims_storage, {BobNode, Host}) end, 1),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/ban ", (_BinId = integer_to_binary(BobId))/binary>>)),
			BobBanMsg2 = escalus:wait_for_stanza(Alice),
			#message{body = [#text{data = <<"banned accounts:\n\tmain account whale.bob@localhost\n\tsub-account whale.clara@localhost">>}]} = xmpp:decode(BobBanMsg2),
%%			BanMsgId = <<BinId/binary, " has been banned">>,
			true = wait_for_result(fun() -> mod_adhoc_eims:is_banned(BobJ) end, true),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?unban), " ", BobNick/binary>>)),
			UnBanNickMsg = <<BobNick/binary, " has been unbanned">>,
			escalus:assert(is_groupchat_message, [UnBanNickMsg], escalus:wait_for_stanza(Alice)),
			false = wait_for_result(fun() -> mod_adhoc_eims:is_banned(BobJ) end, false),


			FakeUser = <<"fakeuser">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?ban), " ", FakeUser/binary>>)),
			InvalidBanMsg = <<FakeUser/binary, " not found">>,
			escalus:assert(is_groupchat_message, [InvalidBanMsg], escalus:wait_for_stanza(Alice)),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?unban), " ", FakeUser/binary>>)),
			escalus:assert(is_groupchat_message, [InvalidBanMsg], escalus:wait_for_stanza(Alice)),
			false = wait_for_result(fun() -> mod_adhoc_eims:is_banned(jid:make(BobNode, Host)) end, false),

			%% verify of the global ban
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?ban), " ", ClaraJid/binary, " all">>)),
			escalus:wait_for_stanzas(Alice, 1),
			[{_, false} = wait_for_result(fun() -> ejabberd_auth_eims:check_password(Node, Node, Host, Pwd) end, fun({_, false}) -> true; (_) -> false end)
				|| {Node, Pwd} <- lists:zip(WhaleNodes, WhalePwds)],
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/unban ", ClaraJid/binary, " all">>)),
			[UnBanMsg] = escalus:wait_for_stanzas(Alice, 1),
			UnBanMainA = <<ClaraNode/binary, "`s main account has been unbanned">>,
			#message{body = [#text{data = UnBanMainA}]} = xmpp:decode(UnBanMsg),
			ok = wait_for_result(fun() -> mnesia:dirty_delete(eims_storage, {BobNode, Host}) end, ok),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/ban ", ClaraJid/binary, " all">>)),
			escalus:wait_for_stanzas(Alice, 1), %% TODO we are temporarily expecting one message, although earlier there were two, but they were not sent...
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/banned">>)),
			[BannedMsg1] = escalus:wait_for_stanzas(Alice, 1),
			#message{body = [#text{data = <<"banned users:\n\twhale.clara`s main account">>}]} = xmpp:decode(BannedMsg1),
			[ejabberd_auth_eims:check_password(Node, Node, Host, Pwd)
				|| {Node, Pwd} <- lists:zip(WhaleNodes, WhalePwds)],
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/banned">>)),
			[BannedMsg2] = escalus:wait_for_stanzas(Alice, 1),
			#message{body = [#text{data = <<"banned users:\n\twhale.bob`s main account">>}]} = xmpp:decode(BannedMsg2),
			ok
		end),

	[mnesia:dirty_delete(eims_storage, {Node, Host}) || Node <- WhaleNodes],
	[{_, true} = ejabberd_auth_eims:check_password(Node, Node, Host, Pwd)
		|| {Node, Pwd} <- lists:zip(WhaleNodes, WhalePwds)],
	ok = mod_adhoc_eims:set_access(jid:make(BobNode, Host), deny),
	[{_, false} = ejabberd_auth_eims:check_password(Node, Node, Host, Pwd)
		|| {Node, Pwd} <- lists:zip(WhaleNodes, WhalePwds)],
	ok = mod_adhoc_eims:set_access(jid:make(ClaraNode, Host), deny),
	[true = mod_adhoc_eims:is_banned(jid:make(Node, Host)) || Node <- WhaleNodes].

admin_kick_ban_story(Config) ->
	RoomJid = do_test_room_jid(),
	[AliceNick, BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	[Room, RoomHost] = binary:split(RoomJid, <<"@">>),
	Host = escalus_config:get_ct(ejabberd_domain),
	escalus:story(Config, [{alice, 1}, {bob, 1}, {clara, 1}],
		fun(#client{jid = AliceJid} = Alice,
			#client{jid = BobJid} = Bob,
			#client{jid = ClaraJid} = _Clara) ->
			[AliceNode, _BobNode, ClaraNode] = [hd(binary:split(J, <<"@">>)) || J <- [AliceJid, BobJid, ClaraJid]],
			[_] = wait_for_list(fun() -> mnesia:dirty_read(eims_storage, {ClaraNode, Host}) end, 1),
			%% Alice and Bob enter to ChatRoom
			[] = wait_for_list(fun() -> mod_muc_admin:get_room_affiliations(Room, RoomHost) end),
			do_enter_room(Alice, RoomJid, AliceNick),
			[{AliceNode, _, admin, _}] = %% add "non-whaled" user to admin affiliation
				wait_for_list(fun() -> mod_muc_admin:get_room_affiliations(Room, RoomHost) end, 1),

			do_enter_room(Bob, RoomJid, BobNick),
			escalus_client:wait_for_stanzas(Alice, 2),
			{_, NewBobNick, _} = lists:keyfind(BobJid, 1, mod_muc_admin:get_room_occupants(Room, RoomHost)), %% get "whale" nick
			[{AliceNode, _, admin, _}] = %% bob is not added to affiliation as "whaled" user
				wait_for_list(fun() -> mod_muc_admin:get_room_affiliations(Room, RoomHost) end, 1),
			[_, _] = wait_for_list(fun() -> mod_muc_admin:get_room_occupants(Room, RoomHost) end, 2), %% 2 occupants in room

			%% Alice sends "kick" message to kick Bob
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?kick), " ", NewBobNick/binary>>)),
			escalus:assert(is_presence_with_type, [<<"unavailable">>], escalus:wait_for_stanza(Alice)),
			[_] = wait_for_list(fun() -> mod_muc_admin:get_room_occupants(Room, RoomHost) end, 1),

			do_enter_room(Bob, RoomJid, <<"bob">>),
			escalus_client:wait_for_stanzas(Bob, 6)

			%% Alice sends "rban" message to ban Bob in ChatRoom
%%			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?rban), " ", NewBobNick/binary>>)),
%%			escalus:assert(is_presence_with_type, [<<"unavailable">>], escalus:wait_for_stanza(Bob)),
%%			escalus_client:wait_for_stanzas(Alice, 4),
%%
%%			send(Bob, enter_groupchat(Bob, RoomJid, BobNick)),
%%			escalus:assert(is_presence_with_type, [<<"unavailable">>], escalus:wait_for_stanza(Bob)),
%%			escalus_client:wait_for_stanzas(Bob, 1),
%%			[{AliceNode, _, admin, _}, {BobNode, _, outcast, _}] =
%%				mod_muc_admin:get_room_affiliations(Room, RoomHost),
%%			%% Alice sends "runban" message to ban Bob in ChatRoom
%%			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?runban), " whale.bob">>)),
%%			escalus_client:wait_for_stanzas(Alice, 1),
%%			[{AliceNode, _, admin, _}] =
%%				mod_muc_admin:get_room_affiliations(Room, RoomHost),
%%			escalus:assert_many([is_presence, is_presence], enter_room(Bob, RoomJid, BobNick)),
%%			true = mod_mam:is_empty_for_room(Host, Room, RoomHost)
		end).

eims_msg_story(Config) ->
	RoomJid = do_test_room_jid(),
	Nicks = [_AliceNick, _BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	[Room, RoomHost] = binary:split(RoomJid, <<"@">>),
	Host = escalus_config:get_ct(ejabberd_domain),
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = AliceJid} = Alice,
			#client{jid = BobJid} = Bob) ->
			UserNodes = [_AliceNode, _BobNode] = [hd(binary:split(J, <<"@">>)) || J <- [AliceJid, BobJid]],
			Users = lists:zip3(Clients = [Alice, Bob], Nicks, UserNodes),
			[do_enter_room(Client, RoomJid, Nick) || {Client, Nick, _} <- Users],
			{_, NewBobNick, _} = lists:keyfind(BobJid, 1, mod_muc_admin:get_room_occupants(Room, RoomHost)), %% get "whale" nick
			[escalus:wait_for_stanzas(C, 2) || C <- Clients],
			Number = 20,
			[begin
				 send(Client, escalus_stanza:groupchat_to(RoomJid, <<Nick/binary, " test", (integer_to_binary(I))/binary>>)),
				 [escalus:wait_for_stanza(C) || C <- Clients]
			 end || {Client, Nick, _} <- Users, I <- lists:seq(1, Number + 1)],

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/",?b(?purge), " ",  NewBobNick/binary>>)),
			[begin
				 Pkt = xmpp:decode(escalus:wait_for_stanza(C)),
				 [true = xmpp:has_subtag(Pkt, Tag) || Tag <- [#fasten_apply_to{}]] %% this no store hint doesn't affect anything, so it's not needed here
			 end || C <- Clients, _I <- lists:seq(1, Number)],
			PurgeSuccessMsg = <<NewBobNick/binary, " messages have been deleted successfully">>,
			escalus:assert(is_groupchat_message, [PurgeSuccessMsg], escalus:wait_for_stanza(Alice)),
			Number = wait_for_result(fun() -> length(eims_db:read_archive(Room, RoomHost)) - 1 end, Number),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/",?b(?purge), " all">>)),
			[begin
				 Pkt = xmpp:decode(escalus:wait_for_stanza(C)),
				 [true = xmpp:has_subtag(Pkt, Tag) || Tag <- [#fasten_apply_to{}]]
			 end || C <- Clients, _I <- lists:seq(1, Number)],
			PurgeAllSuccessMsg = <<"all messages have been deleted successfully">>,
			escalus:assert(is_groupchat_message, [PurgeAllSuccessMsg], escalus:wait_for_stanza(Alice)),
			true = mod_mam:is_empty_for_room(Host, Room, RoomHost),

			%% test for success
			[_FirstBobMsg | _] =
				lists:flatten(
					[begin
						 send(Bob, escalus_stanza:groupchat_to(RoomJid, <<NewBobNick/binary, " test remove by id ", (integer_to_binary(I))/binary>>)),
						 [escalus:wait_for_stanza(C) || C <- Clients]
					 end || I <- lists:seq(1, 2)]),
%%			#mam_archived{id = MamId} = xmpp:get_subtag(xmpp:decode(FirstBobMsg), #mam_archived{}),
%%			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?delmsg), " ", MamId/binary>>)),
%%			[escalus:wait_for_stanza(C) || C <- Clients],
%%			DelMsgSuccess = <<"the message ", MamId/binary, " is deleted">>,
%%			escalus:assert(is_groupchat_message, [DelMsgSuccess], escalus:wait_for_stanza(Alice)),
			false = wait_for_result(fun() -> mod_mam:is_empty_for_room(Host, Room, RoomHost) end, false),
			ok
		end).

member_story(Config) ->
	RoomJid = do_test_room_jid(),
	Nicks = [_AliceNick, _BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	[Room, RoomHost] = binary:split(RoomJid, <<"@">>),
	_Host = escalus_config:get_ct(ejabberd_domain),
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = AliceJid} = Alice,
			#client{jid = BobJid} = Bob) ->
			UserNodes = [_AliceNode, _BobNode] = [hd(binary:split(J, <<"@">>)) || J <- [AliceJid, BobJid]],
			Users = lists:zip3(Clients = [Alice, Bob], Nicks, UserNodes),
			[do_enter_room(Client, RoomJid, Nick) || {Client, Nick, _} <- Users],
			{_, NewBobNick, _} = lists:keyfind(BobJid, 1, mod_muc_admin:get_room_occupants(Room, RoomHost)), %% get "whale" nick
			[escalus:wait_for_stanzas(C, 2) || C <- Clients],
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?iserv_auth)>>)),
			#message{body = [#text{data = <<"https:", _/binary>>}]} = xmpp:decode(escalus:wait_for_stanza(Alice)),

			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?iserv_auth)>>)),
			#message{body = [#text{data = <<"You do not have access ", _/binary>>}]} = xmpp:decode(escalus:wait_for_stanza(Bob)),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?admin), " fakenick">>)),
			escalus:assert(is_groupchat_message, [<<"Occupant \"fakenick\" not found in the room">>], escalus:wait_for_stanza(Alice)),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?member), " fakenick">>)),
			escalus:assert(is_groupchat_message, [<<"Occupant \"fakenick\" not found in the room">>], escalus:wait_for_stanza(Alice)),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?admin), " ", NewBobNick/binary>>)),
			[escalus:wait_for_stanzas(C, 1) || C <- Clients],
			admin = mod_muc_admin:get_room_affiliation(Room, RoomHost, BobJid),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?member), " ", NewBobNick/binary>>)),
			[escalus:wait_for_stanzas(C, 1) || C <- Clients],
			member = mod_muc_admin:get_room_affiliation(Room, RoomHost, BobJid),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?mute), " ", NewBobNick/binary>>)),
			[escalus:wait_for_stanzas(C, 1) || C <- Clients],
			none = mod_muc_admin:get_room_affiliation(Room, RoomHost, BobJid)
		end).

scheduler_story(Config) ->
	escalus:story(Config, [{alice, 1}],
		fun(#client{jid = AliceJid} = Alice) ->
			AliceJID = jid:from_string(AliceJid),
			eims:send_delay_check({AliceJID, 1}, do_send_fun({AliceJID, 1}, 0, self()), 0),
			do_receive_delay_msg(calendar:datetime_to_gregorian_seconds(calendar:local_time())),
			escalus_client:stop(Config, Alice),
			[] = wait_for_result(fun() -> eims:get_tokens(AliceJID) end, [])
		end).

eims_token_story(Config) ->
	RoomJid = do_test_room_jid(),
	Host = escalus_config:get_ct(ejabberd_domain),
	_Nicks = [AliceNick, BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	_Nodes = [_AliceNode, BobNode] = [escalus_config:get_ct({escalus_users, U, username}) || U <- [alice, bob]],
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = AliceJid} = Alice,
			#client{jid = BobJid} = Bob) ->
			#xmlel{name = <<"eims">>} = eims:get_from_private(BobJID = jid:decode(BobJid)),
			{BobNode, _, _} = jid:split(BobJID),
			BobAccessToken = BobNode = eims_rest:get_access_token(BobJID),
			T1 = erlang:system_time(millisecond),
			NewBobToken = wait_for_result(fun() -> eims_rest:get_access_token(BobJID) end, fun(Arg) when Arg == BobAccessToken -> false; (_) -> true end),
			?assert(NewBobToken /= BobAccessToken), %% verify refresh token for Bob
			T2 = erlang:system_time(millisecond),
			?assert(T2 - T1 > 1000), %% take a new token in a second

			#message{from = BotComponentJID, body = []} = TokenPkt = xmpp:decode(escalus:wait_for_stanza(Bob)), %% send token to client
			#message_payload{datatype = ?NS_TOKEN_TYPE, json = #payload_json{data = Json}} = xmpp:get_subtag(TokenPkt, #message_payload{}),
			#{<<"access_token">> := NewBobToken, <<"refresh_token">> := _RefreshToken} = jiffy:decode(Json, [return_maps]),
			application:set_env(ejabberd, refresh_token_http_code, 400),
			{error, bad_request, _Error} = wait_for_result(fun() -> eims_rest:get_access_token(BobJID) end,
				fun({error, bad_request, _Error}) -> true; (_) -> false end),
			?assert(erlang:system_time(millisecond) - T2 > 1000),
			do_enter_room(Bob, RoomJid, BobNick),
			[_] = escalus:wait_for_stanzas(Bob, 1),
			escalus_client:stop(Config, Bob),
			[] = eims:get_tokens(BobJID),

			application:set_env(ejabberd, refresh_token_http_code, 200),
			do_enter_room(Alice, RoomJid, AliceNick),
			escalus:wait_for_stanzas(Alice, 1),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?iserv_auth)>>)),
			#message{body = [#text{data = <<"https:", _/binary>>}]} = xmpp:decode(escalus:wait_for_stanza(Alice)),
			AuthNonce = eims:get_tokens(AliceJID = jid:decode(AliceJid)),
			?assert(is_integer(AuthNonce)),
			UriMap = uri_string:parse(eims_rest:redirect_uri()),
			State = base64:encode(term_to_binary(#{jid => AliceJid, nonce => AuthNonce})),
			Url = uri_string:normalize(UriMap#{query => uri_string:compose_query([{"code", "hahscode"}, {"state", State}])}),
			{ok, {{_, 200, "OK"}, _, "\"ok\""}} = httpc:request(get, {Url, []}, [], []),
			AccessToken = eims_rest:get_access_token(AliceJID),
			?assert(is_binary(AccessToken)),
			T4 = erlang:system_time(millisecond),
			NewAliceToken = wait_for_result(fun() -> eims_rest:get_access_token(AliceJID) end,
											fun(Arg) when Arg == AccessToken -> false; (_) -> true end),
			?assert(NewAliceToken /= AccessToken), %% verify refresh token for Bob
			?assert(erlang:system_time(millisecond) - T4 > 1000), %% take a new token in a second
			[#message{from = BotComponentJID}, #message{from = BotComponentJID}] =
				[xmpp:decode(P)|| P <- escalus:wait_for_stanzas(Alice, 2)],
			escalus_client:stop(Config, Alice),
			[] = eims:get_tokens(AliceJID)
		end).

eims_filter_story(Config) ->
	RoomJid = do_test_room_jid(),
	[AliceNick, BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	Link = <<"http://fake.com">>,
	IServLink = <<"https://test.iservice.com">>,
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = _AliceJid} = Alice,
			#client{jid = _BobJid} = Bob) ->
			Clients = [Alice, Bob],
			do_enter_room(Alice, RoomJid, AliceNick),
			do_enter_room(Bob, RoomJid, BobNick),
			[escalus:wait_for_stanzas(Client, 2) || Client <- Clients],
			send(Bob, escalus_stanza:groupchat_to(RoomJid, Link)),
			[escalus:assert(is_groupchat_message, [<<"[bot removed link]">>], escalus:wait_for_stanza(Client)) || Client <- Clients],

			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<IServLink/binary, "@attacker.com ", IServLink/binary>>)),
			[escalus:assert(is_groupchat_message, [<<"[bot removed link] ", IServLink/binary>>], escalus:wait_for_stanza(Client)) || Client <- Clients],

			send(Bob, escalus_stanza:groupchat_to(RoomJid, IServLink)),
			[IServLinkMsg, _] = LinkMsgs = [escalus:wait_for_stanza(Client) || Client <- Clients],
			[escalus:assert(is_groupchat_message, [IServLink], LinkMsg) || LinkMsg <- LinkMsgs],
			?assert(<<>> /= eims:get_origin_id(#archive_msg{packet = IServLinkMsg})),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, Link)),
			[escalus:assert(is_groupchat_message, [Link], escalus:wait_for_stanza(Client)) || Client <- Clients]
		end).

eims_post_story(Config) ->
	TestRoomJid = do_test_room_jid(),
	PostRoomJid = do_room_jid(eims_info),
	[AliceNick, BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	[TestRoom, RoomHost] = binary:split(TestRoomJid, <<"@">>),
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = _AliceJid} = Alice,
			#client{jid = _BobJid} = Bob) ->
			do_enter_room(Alice, PostRoomJid, AliceNick),
			do_enter_room(Bob, TestRoomJid, BobNick),
			escalus:wait_for_stanzas(Bob, 1),

			send(Alice, escalus_stanza:groupchat_to(PostRoomJid, <<"/", ?b(?post), " ", TestRoomJid/binary, " POST TEST!">>)),
			escalus:assert(is_groupchat_message, [<<"POST TEST!">>], PostMsg = escalus:wait_for_stanza(Bob)),
			#message{from = {jid, _, _, AliceNick, _, _, _}, sub_els = [#mam_archived{} | _]} = DecPostMsg = xmpp:decode(PostMsg),
			#origin_id{id = OriginId} = xmpp:get_subtag(DecPostMsg, #origin_id{}),
			[_] = wait_for_list(fun() -> eims_db:select_by_origin_id(groupchat, {TestRoom, RoomHost}, OriginId) end, 1),
			[#message{body = [#text{data = <<"POST TEST!">>}]}] = eims:select_history({TestRoom, RoomHost}),
			send(Alice, escalus_stanza:groupchat_to(PostRoomJid, <<"/", ?b(?post), " ", TestRoom/binary, " POST TEST SHORT!">>)),
			escalus:assert(is_groupchat_message, [<<"POST TEST SHORT!">>], escalus:wait_for_stanza(Bob))
		end).

%%-define(UPD_TEXT(Cmd), <<" /", Cmd/binary, " command successfully updated">>).
%%-define(DEL_TEXT(Cmd), <<" /", Cmd/binary, " command successfully deleted">>).
%%-define(CUSTOM_UPD_TEXT(Cmd), <<" /", Cmd/binary, " command doc is succesfully updated">>).
%%-define(CUSTOM_DEFAULT_TEXT(Cmd), <<" /", Cmd/binary, " custom command doc text set to default">>).
%%-define(CUSTOM_INCLUDE_TEXT(Cmd), <<" /", Cmd/binary, " command cannot be updated. Custom command cannot include other custom command">>).
%%-define(CUSTOM_BASE_TEXT(Cmd), <<" /", Cmd/binary, " is base command and cannot be updated">>).

eims_custom_story(Config) ->
	RoomJid = do_test_room_jid(),
	[AliceNick, BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = _AliceJid} = Alice,
			#client{jid = _BobJid} = Bob) ->
			Clients = [Alice, Bob],
			do_enter_room(Alice, RoomJid, AliceNick),
			do_enter_room(Bob, RoomJid, BobNick),
			[escalus:wait_for_stanzas(Client, 2) || Client <- Clients],

			CustomCmd = <<"test_custom">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/upd$", CustomCmd/binary, " /tv 7d">>)),
			escalus:assert(is_groupchat_message, [?UPD_TEXT(CustomCmd)], escalus:wait_for_stanza(Alice)),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", CustomCmd/binary>>)),
			[TvMsg] = escalus:wait_for_stanzas(Alice, 1),
			#message{body = [#text{data = <<"Token", _/binary>>}]} = xmpp:decode(TvMsg),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/upd$", CustomCmd/binary>>)),
			escalus:assert(is_groupchat_message, [?DEL_TEXT(CustomCmd)], escalus:wait_for_stanza(Alice)),
			[] = wait_for_list(fun() -> mnesia:dirty_read(eims_cmd, CustomCmd) end),

			TextCmd = <<"test_text">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/upd$", TextCmd/binary, " TEXT!">>)),
			escalus:assert(is_groupchat_message, [?UPD_TEXT(TextCmd)], escalus:wait_for_stanza(Alice)),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", TextCmd/binary>>)),
			escalus:assert(is_groupchat_message, [<<"TEXT!">>], AlicePkt = escalus:wait_for_stanza(Alice)),
			true = xmpp:has_subtag(xmpp:decode(AlicePkt), #origin_id{}),
			escalus:wait_for_stanzas(Bob, 1),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/upd$", TextCmd/binary>>)),
			escalus:assert(is_groupchat_message, [?DEL_TEXT(TextCmd)], escalus:wait_for_stanza(Alice)),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/upd$", CustomCmd/binary, " /position BTC-PERPETUAL">>)),
			escalus:assert(is_groupchat_message, [?UPD_TEXT(CustomCmd)], escalus:wait_for_stanza(Alice)),

			HelpCmd = <<"summary help">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?help), " ", CustomCmd/binary, " ", HelpCmd/binary>>)),
			escalus:assert(is_groupchat_message, [?CUSTOM_UPD_TEXT(CustomCmd)], escalus:wait_for_stanza(Alice)),
			[#eims_cmd{doc = HelpCmd}] = mnesia:dirty_read(eims_cmd, CustomCmd),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?help), " ", CustomCmd/binary>>)),
			escalus:assert(is_groupchat_message, [?CUSTOM_DEFAULT_TEXT(CustomCmd)], escalus:wait_for_stanza(Alice)),
			[#eims_cmd{doc = undefined}] = mnesia:dirty_read(eims_cmd, CustomCmd),


			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/", CustomCmd/binary>>)),
			escalus:assert(is_groupchat_message, [<<"ERROR: Access denied">>], escalus:wait_for_stanza(Bob)),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/upd$", CustomCmd/binary>>)),
			escalus:assert(is_groupchat_message, [?DEL_TEXT(CustomCmd)], escalus:wait_for_stanza(Alice)),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/upd$", CustomCmd/binary, " /other">>)),
			escalus:assert(is_groupchat_message, [?CUSTOM_INCLUDE_TEXT(CustomCmd)], escalus:wait_for_stanza(Alice)),

%%			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/upd$", ?b(?tv), " fake text">>)),
%%			escalus:assert(is_groupchat_message, [?CUSTOM_BASE_TEXT(?tv)], escalus:wait_for_stanza(Alice)),
			ok
		end).

eims_badwords_story(Config) ->
	RoomJid = do_test_room_jid(),
	[AliceNick, BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	[Room, Server] = binary:split(RoomJid, <<"@">>),
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = _AliceJid} = Alice,
			#client{jid = _BobJid} = Bob) ->
			Clients = [Alice, Bob],
			do_enter_room(Alice, RoomJid, AliceNick),
			do_enter_room(Bob, RoomJid, BobNick),
			[escalus:wait_for_stanzas(Client, 2) || Client <- Clients],
			send(Bob, escalus_stanza:groupchat_to(RoomJid, BobMsg = <<"Alice is bitch!">>)),
			BobStarMsg = <<"Alice is ****">>,
			[escalus:assert(is_groupchat_message, [BobStarMsg], escalus:wait_for_stanza(Client)) ||
				Client <- Clients],
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"fuck you!">>)),
			[escalus:assert(is_groupchat_message, [<<"**** you!">>], escalus:wait_for_stanza(Client)) ||
				Client <- Clients],

			%% edit badwords test
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"Alice is funny!">>)),
			[Pkt, _] = [#message{body = [#text{data = <<"Alice is funny!">>}]} = xmpp:decode(escalus:wait_for_stanza(Client)) || Client <- Clients],
			#origin_id{id = OriginId} = xmpp:get_subtag(Pkt, #origin_id{}),
			EditPkt = xmpp:decode(escalus_stanza:groupchat_to(RoomJid, BobMsg)),
			EditPkt2 = EditPkt#message{sub_els = [#chatstate{type = active}, #replace{id = OriginId}]},
			send(Bob, EditPkt2),
			[escalus:assert(is_groupchat_message, [BobStarMsg], escalus:wait_for_stanza(Client)) ||
				Client <- Clients],

			[#archive_msg{packet = ArcPkt}] = eims_db:select_by_origin_id(groupchat, {Room, Server}, OriginId),
			#message{body = [#text{data = BobStarMsg}]} = xmpp:decode(ArcPkt),

			%% /edit badwords test
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"Alice is funny!">>)),
			[Pkt2, _] = [#message{body = [#text{data = <<"Alice is funny!">>}]} = xmpp:decode(escalus:wait_for_stanza(Client)) || Client <- Clients],
			#origin_id{id = OriginId2} = xmpp:get_subtag(Pkt2, #origin_id{}),

			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?edit), " ", BobMsg/binary>>)),
			[escalus:assert(is_groupchat_message, [BobStarMsg], escalus:wait_for_stanza(Client)) ||
				Client <- Clients],

			[#archive_msg{packet = ArcPkt2}] = eims_db:select_by_origin_id(groupchat, {Room, Server}, OriginId2),
			#message{body = [#text{data = BobStarMsg}]} = xmpp:decode(ArcPkt2),

			%% add bad word to blacklist
			BadWord = <<"b@dword">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?badwords), " en ", BadWord/binary>>)),
			#message{body = [#text{data = <<"\"b@dword\" successfully added", _/binary>>}]} =
				xmpp:decode(escalus:wait_for_stanza(Alice)),
			BlacklistFile = mod_http_eims_api:get_banword_file(en),
			BlackList = mod_http_eims_api:readlines(BlacklistFile),
			true = lists:member(BadWord, BlackList),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, BadWord)),
			[escalus:assert(is_groupchat_message, [<<"****">>], escalus:wait_for_stanza(Client)) ||
				Client <- Clients],
			InvalidBadWord = <<"am">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?badwords), " en ", InvalidBadWord/binary>>)),
			escalus:assert(is_groupchat_message,
				[<<"bad word must have at least 3 characters">>], escalus:wait_for_stanza(Alice)),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/",?b(?badwords)," fakelang ", BadWord/binary>>)),
			escalus:assert(is_groupchat_message,
				[<<"fakelang blacklist not found">>], escalus:wait_for_stanza(Alice)),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/",?b(?badwords)," fakelang">>)),
			escalus:assert(is_groupchat_message,
				[<<"Blacklist for \"fakelang\" language not found">>], escalus:wait_for_stanza(Alice)),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/",?b(?badwords)," en">>)),
			#message{body = [#text{data = <<"http", _/binary>>}]} = xmpp:decode(escalus:wait_for_stanza(Alice)),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/",?b(?badwords)>>)),
			#message{body = [#text{data = BlacklistLink = <<"http", _/binary>>}]} = xmpp:decode(escalus:wait_for_stanza(Alice)),
			{ok, {{_, 200, _}, _, _}} = httpc:request(get, {binary_to_list(BlacklistLink), []}, [], []),

			BlacklistUri = #{query := Query} = uri_string:parse(BlacklistLink),
			{ok, {{_, 200, _}, _, _}} = httpc:request(get, {GetBlacklistUri = uri_string:normalize(BlacklistUri#{path => "eims/blacklist"}), []}, [], []),

			{ok, {{_, 400, "Bad Request"}, _, "{\"error\":\"access denied\"}"}} =
				httpc:request(get, {GetBlacklistUri++["1"], []}, [], []), %% set invalid hash

			[{<<"lang">>, <<"default">>} | _] = DisQuery = uri_string:dissect_query(Query),
			RemoveData = #{<<"args">> => QueryMap = maps:from_list(DisQuery), <<"remove">> => [BadWord], <<"checksum">> => 1},

			PostQuery = io_lib:format("acc=~s", [uri_string:quote(jiffy:encode(RemoveData))]),
			{ok, {{_, 200, "OK"}, _, "Blacklist was successfully updated"}} =
				httpc:request(post, {uri_string:normalize(GetBlacklistUri),
							[], "application/x-www-form-urlencoded", PostQuery}, [], []),

			WrongData = RemoveData#{<<"args">> => QueryMap#{<<"t">> => <<"1">>}}, %% set invalid time
			WrongQuery = io_lib:format("acc=~s", [uri_string:quote(jiffy:encode(WrongData))]),
			{ok, {{_, 400, "Bad Request"}, _, "\"not allowed\""}} =
				httpc:request(post, {uri_string:normalize(GetBlacklistUri),
							[], "application/x-www-form-urlencoded", WrongQuery}, [], []),

			BlackList2 = [_ | _] = mod_http_eims_api:readlines(BlacklistFile),
			false = lists:member(BadWord, BlackList2),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, BadWord)),
			[escalus:assert(is_groupchat_message, [BadWord], escalus:wait_for_stanza(Client)) ||
				Client <- Clients],
			ok
		end).


eims_adhoc_story(Config) ->
	Host = escalus_config:get_ct(ejabberd_domain),
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = _AliceJid} = Alice,
			#client{jid = _BobJid} = Bob) ->
			CommandIq = #xmlel{attrs = Attrs, children = [Query = #xmlel{attrs = QueryAttrs}]} =
				escalus_stanza:iq_get(?NS_DISCO_ITEMS, []),
			send(Alice, CmdIq = CommandIq#xmlel{
				attrs = [{<<"xmlns">>, ?NS_CLIENT}, {<<"to">>, Host} | Attrs],
				children =
				[Query#xmlel{attrs = [{<<"node">>, ?NS_COMMANDS} | QueryAttrs]}]}),
			escalus:assert(is_iq_result, AliceIQResult = escalus:wait_for_stanza(Alice)),
			#iq{sub_els = [#disco_items{items = AliceItems}]} = xmpp:decode(AliceIQResult),
			#disco_item{name = <<"Ban Account...">>} = lists:keyfind(?NS_NODE_BAN, #disco_item.node, AliceItems),

			send(Bob, CmdIq),
			escalus:assert(is_iq_result, BobIQResult = escalus:wait_for_stanza(Bob)),
			#iq{sub_els = [#disco_items{items = BobItems}]} = xmpp:decode(BobIQResult),
			false = lists:keyfind(?NS_NODE_BAN, #disco_item.node, BobItems)
		end).

eims_moderate_story(Config) ->
	RoomJid = do_test_room_jid(),
	[AliceNick, BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	[Room, RoomHost] = binary:split(RoomJid, <<"@">>),
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = AliceJid} = Alice,
			#client{jid = BobJid} = Bob) ->
			DiscoInfoIq = #xmlel{attrs = Attrs} =
				escalus_stanza:iq_get(?NS_DISCO_INFO, []),
			send(Alice, DiscoInfoIq#xmlel{attrs = [{<<"to">>, RoomJid} | Attrs]}),
			#iq{sub_els = [#disco_info{features = Features}]} = xmpp:decode(escalus:wait_for_stanza(Alice)),
			true = lists:member(?NS_MESSAGE_MODERATE, Features),
			true = lists:member(?NS_REPLY, Features),
			Clients = [Alice, Bob],
			do_enter_room(Alice, RoomJid, AliceNick),
			do_enter_room(Bob, RoomJid, BobNick),
			[escalus:wait_for_stanzas(Client, 2) || Client <- Clients],
			BobText = <<"moderate me">>, BobText2 = <<"moderate me edited">>,
			send(Bob, escalus_stanza:groupchat_to(RoomJid, BobText)),
			[BobMsg | _] = [escalus:wait_for_stanza(Client) || Client <- Clients],

			#message{sub_els = [#mam_archived{id = BobStanzaId} | _], body = [#text{data = BobText}]}
				= xmpp:decode(BobMsg),
			AliceModerateIq = #iq{type = set, from = jid:decode(AliceJid), to = RoomJID = jid:decode(RoomJid),
				sub_els = [AliceApply = #fasten_apply_to{id = BobStanzaId, sub_els =
				AliceSubEls =
					[#message_moderate_21{retract = #retract_id{}, reason = <<"removed by admin">>}
%%						#moderate{sub_els = [#retract_id{},
%%						#jingle_reason{text = [#text{data = <<"removed by admin">>}]}]}
					]}]},
			send(Alice, AliceModerateIq),
			escalus:assert(is_iq_result, escalus:wait_for_stanza(Alice)),
			RoomAliceNick = jid:replace_resource(RoomJID, AliceNick),
			[#fasten_apply_to{sub_els = [#message_moderated_21{by = RoomAliceNick}]} =
				xmpp:get_subtag(xmpp:decode(escalus:wait_for_stanza(Client)), #fasten_apply_to{})
				|| Client <- Clients],
			[] = wait_for_list(fun() -> eims_db:read_archive(Room, RoomHost) end),
			[] = wait_for_list(fun() -> eims:select_history({Room, RoomHost}) end),

			send(Bob, escalus_stanza:groupchat_to(RoomJid, BobText)),
			[BobMsg2 | _] = [escalus:wait_for_stanza(Client) || Client <- Clients],

			DecBobMsg2 = #message{body = [#text{data = BobText}], sub_els = [#mam_archived{id = BobStanzaId2} | _]} = xmpp:decode(BobMsg2),
			#origin_id{id = OriginId} = xmpp:get_subtag(DecBobMsg2, #origin_id{}),

			EditPkt = xmpp:decode(escalus_stanza:groupchat_to(RoomJid, BobText2)),
			EditPkt2 = EditPkt#message{sub_els = [#chatstate{type = active}, #replace{id = OriginId}, #origin_id{id = _EditOriginId = <<"2">>}]},
			send(Bob, EditPkt2),
			[false = xmpp:has_subtag(#message{sub_els = [#mam_archived{id = BobStanzaId2} | _], body = [#text{data = BobText2}]} =
				xmpp:decode(escalus:wait_for_stanza(Client)), #stanza_id{}) || Client <- Clients],

			AliceModerateIq2 = AliceModerateIq#iq{
				sub_els = [AliceApply#fasten_apply_to{id = BobStanzaId2, sub_els = AliceSubEls}]},

			send(Alice, AliceModerateIq2),
			escalus:assert(is_iq_result, escalus:wait_for_stanza(Alice)),
			[#fasten_apply_to{sub_els = [#message_moderated_21{by = RoomAliceNick}]} =
				xmpp:get_subtag(xmpp:decode(escalus:wait_for_stanza(Client)), #fasten_apply_to{})
				|| Client <- Clients],

			[] = wait_for_list(fun() -> eims_db:read_archive(Room, RoomHost) end),
			[] = wait_for_list(fun() -> eims:select_history({Room, RoomHost}) end),

			AliceText = <<"moderate me, Bob">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, AliceText)),
			[AliceMsg | _] = [escalus:wait_for_stanza(Client) || Client <- Clients],
			#message{sub_els = [#mam_archived{id = AliceStanzaId} | _],
				body = [#text{data = AliceText}]} = xmpp:decode(AliceMsg),

			BobModerateIq = AliceModerateIq#iq{from = jid:decode(BobJid),
				sub_els = [AliceApply#fasten_apply_to{id = AliceStanzaId}]},
			send(Bob, BobModerateIq),
			escalus:assert(is_iq_error, escalus:wait_for_stanza(Bob)),
			[_] = wait_for_list(fun() -> eims_db:read_archive(Room, RoomHost) end, 1),
			ok
		end).

muc_manipulation_story(Config) ->
	RoomJid = do_test_room_jid(),
	[AliceNick, BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	MUC = proplists:get_value(muc, Config, <<"tmp_muc">>),
	MUCTitle = proplists:get_value(muc_title, Config, <<"tmp_muc">>),
	Host = hd(ejabberd_option:hosts()),
	MucHost = mod_muc_opt:host(Host),
	MUCJid = jid:to_string({MUC, MucHost, <<>>}),
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = AliceJid} = Alice,
			#client{jid = BobJid} = Bob) ->
			Clients = [Alice, Bob],
			do_enter_room(Alice, RoomJid, AliceNick),
			do_enter_room(Bob, RoomJid, BobNick),
			[escalus:wait_for_stanzas(Client, 2) || Client <- Clients],
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?muc), " priv ", MUCTitle/binary>>)),
			escalus:assert(is_groupchat_message, [<<"Room ", MUCJid/binary, " successfully created">>], escalus:wait_for_stanza(Alice)),
			<<"false">> = config(<<"public">>, mod_muc_admin:get_room_options(MUC, MucHost)),
			_UserNodes = [AliceNode, _BobNode] = [hd(binary:split(J, <<"@">>)) || J <- [AliceJid, BobJid]],
			[{AliceNode, _, owner, _}] = wait_for_list(fun() -> mod_muc_admin:get_room_affiliations(MUC, MucHost) end, 1),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?muc), " del ", MUC/binary>>)),
			escalus:assert(is_groupchat_message, [<<"Room ", MUCJid/binary, " successfully deleted">>], escalus:wait_for_stanza(Alice)),
			timer:sleep(300),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?muc), " pub ", MUCTitle/binary>>)),
			escalus:assert(is_groupchat_message, [<<"Room ", MUCJid/binary, " successfully created">>], escalus:wait_for_stanza(Alice)),
			<<"true">> = config(<<"public">>, mod_muc_admin:get_room_options(MUC, MucHost)),
			MUCTitle = config(<<"title">>, mod_muc_admin:get_room_options(MUC, MucHost)),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?muc), " pub ", MUCTitle/binary>>)),
			escalus:assert(is_groupchat_message, [<<"ERROR: Access denied">>], escalus:wait_for_stanza(Bob)),
			KoreanText = <<236, 149, 132, 236, 154, 148>>, %% same as korean "아요"
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?muc), " priv ", KoreanText/binary>>)),
			#message{body = [#text{data = Text}]} = xmpp:decode(escalus:wait_for_stanza(Alice)),
			[<<"Room">>, TmpRoomJid | _] = binary:split(Text, <<" ">>, [global]),
			{TmpRoomNode, _, <<>>} = jid:split(jid:decode(TmpRoomJid)),
			[_Room, RoomHost] = binary:split(RoomJid, <<"@">>),
			ok = mod_muc_admin:destroy_room(TmpRoomNode, RoomHost),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?muc), " invalid ", MUCTitle/binary>>)),
			escalus:assert(is_groupchat_message, [<<"Invalid params for /", ?b(?muc), " command">>], escalus:wait_for_stanza(Alice)),
			ok
		end).

edit_retract_story(Config) ->
	RoomJid = do_test_room_jid(),
	Nicks = [_AliceNick, _BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	[Room, Server] = binary:split(RoomJid, <<"@">>),
%%	Host = escalus_config:get_ct(ejabberd_domain),
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = AliceJid} = Alice,
			#client{jid = BobJid} = Bob) ->
			UserNodes = [_AliceNode, _BobNode] = [hd(binary:split(J, <<"@">>)) || J <- [AliceJid, BobJid]],
			Users = lists:zip3(Clients = [Alice, Bob], Nicks, UserNodes),
			[do_enter_room(Client, RoomJid, Nick) || {Client, Nick, _} <- Users],
			[escalus:wait_for_stanzas(Client, 2) || Client <- Clients],
			Text = <<"text for edit">>, EditText = <<"edited text">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, Text)),
			escalus:assert(is_groupchat_message, [Text], Pkt = escalus:wait_for_stanza(Alice)),
			escalus:wait_for_stanzas(Bob, 1),

			OriginId = eims:get_origin_id(Pkt),
			EditPkt = xmpp:decode(escalus_stanza:groupchat_to(RoomJid, EditText)),
			EditPkt2 = EditPkt#message{sub_els = [#chatstate{type = active}, #replace{id = OriginId}, #origin_id{id = EditOriginId = eims:gen_uuid()}]},
			send(Alice, EditPkt2),
			RecEditPkts = [RecEditPkt, _] = [escalus:wait_for_stanza(Client) || Client <- Clients],
			[EditOriginId = eims:get_origin_id(P) || P <- RecEditPkts],
			[escalus:assert(is_groupchat_message, [EditText], P) || P <- RecEditPkts],
			false = xmpp:has_subtag(xmpp:decode(RecEditPkt), #hint{type = 'no-store'}),
			[#archive_msg{packet = ArcEditPkt}] = eims_db:select_by_origin_id(groupchat, {Room, Server}, OriginId),
			#message{id = OriginId, body = [#text{data = EditText}]} = xmpp:decode(ArcEditPkt), %% message id must be as origin id

			EditText3 = <<"second edited text">>,
			EditPkt3 = EditPkt#message{body = [#text{data = EditText3}],
				sub_els = [#chatstate{type = active}, #replace{id = OriginId}, #origin_id{id = EditOriginId2 = eims:gen_uuid()}]},
			send(Alice, EditPkt3),
			[escalus:wait_for_stanza(Client) || Client <- Clients],
			[#archive_msg{packet = ArcEditPkt2}] = eims_db:select_by_origin_id(groupchat, {Room, Server}, OriginId),
			escalus:assert(is_groupchat_message, [EditText3], ArcEditPkt2),

			RetractPkt = xmpp:set_subtag(EditPkt#message{body = [],
				sub_els = [#fasten_apply_to{id = EditOriginId2, sub_els = [#retract_id{}]},
					#origin_id{id = eims:gen_uuid()}]}, #hint{type = store}),
			send(Alice, RetractPkt),
			[true = xmpp:has_subtag(xmpp:decode(escalus:wait_for_stanza(Client)), #hint{type = store}) || Client <- Clients],
			[] = eims_db:select_by_origin_id(groupchat, {Room, Server}, OriginId),
			ok
		end).

last_edit_story(Config) ->
	RoomJid = do_test_room_jid(),
	Nicks = [_AliceNick, _BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	[Room, Server] = binary:split(RoomJid, <<"@">>),
%%	Host = escalus_config:get_ct(ejabberd_domain),
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = AliceJid} = Alice,
			#client{jid = BobJid} = Bob) ->
			UserNodes = [_AliceNode, _BobNode] = [hd(binary:split(J, <<"@">>)) || J <- [AliceJid, BobJid]],
			Users = lists:zip3(Clients = [Alice, Bob], Nicks, UserNodes),
			[do_enter_room(Client, RoomJid, Nick) || {Client, Nick, _} <- Users],
			[escalus:wait_for_stanzas(Client, 2) || Client <- Clients],
			Text = <<"Hello 1!">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, Text)),

			[Pkt, _] = [#message{body = [#text{data = Text}]} = xmpp:decode(escalus:wait_for_stanza(Client)) || Client <- Clients],
			#origin_id{id = OriginId} = xmpp:get_subtag(Pkt, #origin_id{}),
			Text2 = <<"Hello 2!">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?edit), " ", ?b(Text2)>>)),
			[Pkt2, _] = [#message{body = [#text{data = Text2}]} = xmpp:decode(escalus:wait_for_stanza(Client)) || Client <- Clients],
			#replace{id = OriginId} = xmpp:get_subtag(Pkt2, #replace{}),
			#origin_id{id = OriginId2} = xmpp:get_subtag(Pkt2, #origin_id{}),
			[_] = eims_db:select_by_origin_id(groupchat, {Room, Server}, OriginId),
			[_] = eims_db:select_by_retract_id(groupchat, {Room, Server}, OriginId2),

			Text3 = <<"Hello 3!">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?edit), " ", ?b(Text3)>>)),
			[Pkt3, _] = [#message{body = [#text{data = Text3}]} = xmpp:decode(escalus:wait_for_stanza(Client)) || Client <- Clients],
			#replace{id = OriginId} = xmpp:get_subtag(Pkt3, #replace{}),
			#origin_id{id = OriginId3} = xmpp:get_subtag(Pkt3, #origin_id{}),
			[_] = eims_db:select_by_origin_id(groupchat, {Room, Server}, OriginId),
			[] = eims_db:select_by_retract_id(groupchat, {Room, Server}, OriginId2),
			[] = eims_db:select_by_origin_id(groupchat, {Room, Server}, OriginId2),
			[_] = eims_db:select_by_retract_id(groupchat, {Room, Server}, OriginId3),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?del)>>)),
			[RetractPkt, _] = [#message{body = []} = xmpp:decode(escalus:wait_for_stanza(Client)) || Client <- Clients],
			#fasten_apply_to{id = OriginId3, sub_els = [#retract_id{}]} = xmpp:get_subtag(RetractPkt, #fasten_apply_to{}),
			[] = eims_db:select_by_origin_id(groupchat, {Room, Server}, OriginId),
			[] = eims_db:select_by_retract_id(groupchat, {Room, Server}, OriginId3),
			ok
		end).


p2p_story(Config) ->
	Server = hd(ejabberd_option:hosts()),
	UserNodes = [_AliceNode, _DavidNode] = [escalus_config:get_ct({escalus_users, U, username}) || U <- [alice, david]],
	OriginId = <<"1">>,
	escalus:story(Config, [{alice, 1}, {david, 1}],
		fun(#client{jid = _AliceJid} = Alice,
			#client{jid = _DavidJid} = David) ->
			AliceMsg = <<"Hello, David!">>,
			Clients = [Alice, David],
			[{AliceBareJID, _AliceJID}, {_DavidBareJID, _DavidJID}] = [{jid:replace_resource(jid:decode(J), <<>>), jid:decode(J)} || #client{jid = J} <- Clients],

			AlicePkt = #message{sub_els = AliceEls} = xmpp:decode(escalus_stanza:chat_to_short_jid(David, AliceMsg)),
			send(Alice, AlicePkt#message{sub_els = [#receipt_request{}, #origin_id{id = OriginId} | AliceEls]}),

			escalus:assert(is_chat_message, [AliceMsg], AlicePkt2 = escalus:wait_for_stanza(David)),
			#origin_id{id = OriginId} = xmpp:get_subtag(xmpp:decode(AlicePkt2), #origin_id{}),
			#mam_archived{id = Id} = xmpp:get_subtag(xmpp:decode(AlicePkt2), #mam_archived{}),
			[_, [#archive_msg{id = Id}]] = [[#archive_msg{}] = eims_db:select_by_origin_id(chat, {UserNode, Server}, OriginId) || UserNode <- UserNodes],

			?a(xmpp:has_subtag(xmpp:decode(AlicePkt2), #receipt_request{})),
			DavidRespPkt = #message{to = AliceBareJID, sub_els = [#receipt_response{id = OriginId}, #hint{type = store}]},
			send(David, DavidRespPkt),
			?a(xmpp:has_subtag(xmpp:decode(escalus:wait_for_stanza(Alice)), #receipt_response{})),
			[[_, _] = eims_db:select_by_origin_id(chat, {UserNode, Server}, OriginId) || UserNode <- UserNodes],

			%% edit story
			AliceEditMsg = <<"Hello, David! - 2">>,
			EditPkt = xmpp:decode(escalus_stanza:chat_to_short_jid(David, AliceEditMsg)),
			EditPkt2 = EditPkt#message{sub_els = [#chatstate{type = active}, #receipt_request{},
				#replace{id = OriginId}, #origin_id{id = EditOriginId = <<"2">>}]},
			send(Alice, EditPkt2),
			escalus:assert(is_chat_message, [AliceEditMsg], escalus:wait_for_stanza(David)),

			[[#archive_msg{}], [#archive_msg{id = Id}]] = [[#archive_msg{}] = eims_db:select_by_origin_id(chat, {UserNode, Server}, OriginId) || UserNode <- UserNodes],
			[[#archive_msg{}] = eims_db:select_by_retract_id(chat, {UserNode, Server}, EditOriginId) || UserNode <- UserNodes],

			%% David sends response message
			send(David, _DavidRespDecPkt = xmpp:set_subtag(DavidRespPkt, #receipt_response{id = EditOriginId})),
			?a(xmpp:has_subtag(xmpp:decode(escalus:wait_for_stanza(Alice)), #receipt_response{})),
			[[_, _] = eims_db:select_by_origin_id(chat, {UserNode, Server}, OriginId) || UserNode <- UserNodes],
			[[_, _] = eims_db:select_by_retract_id(chat, {UserNode, Server}, EditOriginId) || UserNode <- UserNodes],

			%% second edit story
			AliceEditMsg2 = <<"Hello, David! - 3">>,
			EditPkt3 = EditPkt#message{body = [#text{data = AliceEditMsg2}], sub_els = [#chatstate{type = active}, #receipt_request{},
				#replace{id = OriginId}, #origin_id{id = EditOriginId2 = <<"3">>}]},
			send(Alice, EditPkt3),
			escalus:assert(is_chat_message, [AliceEditMsg2], escalus:wait_for_stanza(David)),

			[[_] = eims_db:select_by_origin_id(chat, {UserNode, Server}, OriginId) || UserNode <- UserNodes],
			[[] = eims_db:select_by_origin_id(chat, {UserNode, Server}, EditOriginId) || UserNode <- UserNodes],
			[[_] = eims_db:select_by_retract_id(chat, {UserNode, Server}, EditOriginId2) || UserNode <- UserNodes],

			%% retract edited message
			AliceRetractPkt = xmpp:set_subtag(xmpp:set_subtag(AlicePkt#message{body = [#text{data = <<>>}]},
				#fasten_apply_to{id = EditOriginId2, sub_els = [#retract_id{}]}), #hint{type = store}),
			send(Alice, AliceRetractPkt),
			#fasten_apply_to{id = EditOriginId2, sub_els = [#retract_id{}]} = xmpp:get_subtag(xmpp:decode(escalus:wait_for_stanza(David)), #fasten_apply_to{}),
			[[] = eims_db:select_by_origin_id(chat, {UserNode, Server}, OriginId) || UserNode <- UserNodes],
			[[] = eims_db:select_by_retract_id(chat, {UserNode, Server}, EditOriginId2) || UserNode <- UserNodes],

			%% offline retract
			do_logout_user(Config, David),
			send(Alice, AlicePkt#message{sub_els = [#receipt_request{}, #origin_id{id = OriginId = <<"1">>} | AliceEls]}),
			[_] = wait_for_list(fun() -> eims_offline:get_offline_msgs_by_tag(#origin_id{id = OriginId}) end, 1),

			AliceRetractPkt2 = xmpp:set_subtag(AlicePkt#message{body = [#text{data = <<>>}], sub_els = [#hint{type = store}, #origin_id{id = RetractOriginId = <<"retract_1">>}]},
				#fasten_apply_to{id = OriginId, sub_els = [#retract_id{}]}),
			send(Alice, AliceRetractPkt2),
			[] = wait_for_list(fun() -> eims_offline:get_offline_msgs_by_tag(#origin_id{id = OriginId}) end),
			[_] = wait_for_list(fun() -> eims_offline:get_offline_msgs_by_tag(#origin_id{id = RetractOriginId}) end, 1),
			{ok, David2} = escalus_client:start(Config, david, <<"1">>),
			escalus_overridables:do(Config, initial_activity, [David2],
				{escalus_story, send_initial_presence}),

			escalus:assert(is_chat_message, [<<>>], AliceRcvRetractPkt = escalus:wait_for_stanza(David2)),
			#origin_id{id = RetractOriginId} = xmpp:get_subtag(AliceRcvRetractDecPkt = xmpp:decode(AliceRcvRetractPkt), #origin_id{}),
			#fasten_apply_to{id = OriginId, sub_els = [#retract_id{}]} = xmpp:get_subtag(AliceRcvRetractDecPkt, #fasten_apply_to{}),
			escalus:assert(is_presence, escalus:wait_for_stanza(David2)),
			[[] = eims_db:select_by_origin_id(chat, {UserNode, Server}, OriginId) || UserNode <- UserNodes],
			[[] = eims_db:select_by_origin_id(chat, {UserNode, Server}, RetractOriginId) || UserNode <- UserNodes], %% ensure that retract message is not saved to db
			[] = eims_offline:get_offline_msgs_by_tag(#origin_id{id = RetractOriginId}),
			ok
		end).

p2p_offline_story(Config) ->
	Server = hd(ejabberd_option:hosts()),
%%	Nicks = [AliceNick, DavidNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, david]],
	UserNodes = [_AliceNode, _DavidNode] = [escalus_config:get_ct({escalus_users, U, username}) || U <- [alice, david]],
	OriginId = <<"1">>,
	AliceMsg = <<"Hello, David!">>,
	AliceEditMsg = <<"Hello, David! - 2">>,
	AliceEditMsg3 = <<"Hello, David! - 3">>,
	EditOriginId = <<"2">>,
	EditOriginId3 = <<"3">>,
	escalus:story(Config, [{alice, 1}, {david, 1}],
		fun(#client{jid = _AliceJid} = Alice,
			#client{jid = _DavidJid} = David) ->
			do_logout_user(Config, David),
			AlicePkt = #message{} = xmpp:decode(escalus_stanza:chat_to_short_jid(David, AliceMsg)),
			send(Alice, AlicePkt2 = AlicePkt#message{sub_els = [#receipt_request{}, #origin_id{id = OriginId}]}),
			[_] = wait_for_list(fun() -> eims_offline:get_offline_msgs_by_tag(#origin_id{id = OriginId}) end, 1),
			[[#archive_msg{us = {UserNode, Server}}] =
				wait_for_list(fun() -> eims_db:select_by_origin_id(chat, {UserNode, Server}, OriginId) end, 1) || UserNode <- UserNodes],

			EditPkt = xmpp:decode(escalus_stanza:chat_to_short_jid(David, AliceEditMsg)),
			EditPkt2 = EditPkt#message{sub_els = [#chatstate{type = active}, #receipt_request{},
				#replace{id = OriginId}, #origin_id{id = EditOriginId}]},
			send(Alice, EditPkt2),
			[[#message{body = [#text{data = AliceEditMsg}]}] = %% all offline messages with same new text
			wait_for_list(fun() -> eims_offline:get_offline_pkts_by_tag(Tag) end, 1) ||
				Tag <- [#origin_id{id = EditOriginId}, #origin_id{id = OriginId}, #replace{id = OriginId}]],

			%% second offline message replace
			EditPkt3 = EditPkt#message{body = [#text{data = AliceEditMsg3}], sub_els = [#chatstate{type = active}, #receipt_request{},
				#replace{id = OriginId}, #origin_id{id = EditOriginId3}]},
			send(Alice, EditPkt3),
			[_] = wait_for_list(fun() -> eims_offline:get_offline_msgs_by_tag(#origin_id{id = EditOriginId3}) end, 1),
			[_] = wait_for_list(fun() -> eims_offline:get_offline_msgs_by_tag(#origin_id{id = EditOriginId}) end, 1), %% previous replace message must be removed
			[_, _] = wait_for_list(fun() -> eims_offline:get_offline_msgs_by_tag(#replace{id = OriginId}) end, 2),

			%% retract offline message
			AliceRetractPkt = xmpp:set_subtag(AlicePkt#message{body = [#text{data = <<>>}], sub_els = [#hint{type = store}, #origin_id{id = RetractOriginId = <<"retract_1">>}]},
				#fasten_apply_to{id = EditOriginId3, sub_els = [#retract_id{}]}),
			send(Alice, AliceRetractPkt),
			[_] = wait_for_list(fun() -> eims_offline:get_offline_msgs_by_tag(#origin_id{id = RetractOriginId}) end, 1),
			[] = wait_for_list(fun() -> eims_offline:get_offline_msgs_by_tag(#replace{id = OriginId}) end),
			[] = wait_for_list(fun() -> eims_offline:get_offline_msgs_by_tag(#origin_id{id = OriginId}) end),
			[[] = wait_for_list(fun() -> eims_db:select_by_origin_id(chat, {UserNode, Server}, OriginId) end) || UserNode <- UserNodes],

			{ok, David2} = escalus_client:start(Config, david, <<"1">>),
			escalus_overridables:do(Config, initial_activity, [David2],
				{escalus_story, send_initial_presence}),

			escalus:assert(is_chat_message, [<<>>], AliceRcvRetractPkt = escalus:wait_for_stanza(David2)),
			#origin_id{id = RetractOriginId} = xmpp:get_subtag(AliceRcvRetractDecPkt = xmpp:decode(AliceRcvRetractPkt), #origin_id{}),
			#fasten_apply_to{id = EditOriginId3, sub_els = [#retract_id{}]} = xmpp:get_subtag(AliceRcvRetractDecPkt, #fasten_apply_to{}),
			escalus:assert(is_presence, escalus:wait_for_stanza(David2)),

			%% second offline edit test
			do_logout_user(Config, David2),
			[send(Alice, Pkt) || Pkt <- [AlicePkt2, EditPkt2, EditPkt3]], %% send message and 2 edits
			[[_] = wait_for_list(fun() -> eims_offline:get_offline_msgs_by_tag(#origin_id{id = OId}) end, 1) ||
				OId <- [OriginId, EditOriginId, EditOriginId3]],

			{ok, David3} = escalus_client:start(Config, david, <<"1">>),
			escalus_overridables:do(Config, initial_activity, [David3],
				{escalus_story, send_initial_presence}),
			[escalus:assert(is_chat_message, [Msg], escalus:wait_for_stanza(David3)) || Msg <- [AliceEditMsg3, AliceEditMsg, AliceEditMsg3]],
			ok
		end).

pubsub_story(Config) ->
	Server = hd(ejabberd_option:hosts()),
	_UserNodes = [AliceNode, _BobNode] = [escalus_config:get_ct({escalus_users, U, username}) || U <- [alice, bob]],
	RoomJid = do_test_room_jid(),
	_Nicks = [AliceNick, BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	[Room, RoomHost] = binary:split(RoomJid, <<"@">>),
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = AliceJid} = Alice,
			#client{jid = _BobJid} = Bob) ->
			do_enter_room(Bob, RoomJid, BobNick),
			escalus:wait_for_stanzas(Bob, 1),
			{ok, Pid} = eims:subscribe(jid:decode(AliceJid), jid:decode(RoomJid), AliceNick, [<<"urn:xmpp:mucsub:nodes:messages">>]),
			{true, AliceNick, _} = mod_muc_room:is_subscribed(Pid, jid:remove_resource(jid:decode(AliceJid))),
			Text = <<"Hello, Alice!">>,
			send(Bob, xmpp:set_subtag(xmpp:decode(escalus_stanza:groupchat_to(RoomJid, Text)), #origin_id{id = OriginId = <<"1">>})),
			escalus:assert(is_groupchat_message, [Text], escalus:wait_for_stanza(Bob)),
			EventPkt = #message{body = [#text{data = Text}]} = eims:unwrap_mucsub_message(xmpp:decode(escalus:wait_for_stanza(Alice))),
			#origin_id{id = OriginId} = xmpp:get_subtag(EventPkt, #origin_id{}),

			[#archive_msg{}] = eims_db:select_by_origin_id(chat, {AliceNode, Server}, OriginId),
			[_] = wait_for_list(fun() -> eims_db:select_by_origin_id(groupchat, {Room, RoomHost}, OriginId) end, 1),

			%% edit pubsub
			EditText = <<"Edit subscribed Alice">>,
			EditPkt = xmpp:decode(escalus_stanza:groupchat_to(RoomJid, EditText)),
			send(Bob, EditPkt#message{sub_els = [#replace{id = OriginId}, #origin_id{id = EditOriginId = <<"2">>}]}),
			escalus:assert(is_groupchat_message, [EditText], escalus:wait_for_stanza(Bob)),
			[_] = wait_for_list(fun() -> eims_db:select_by_retract_id(groupchat, {Room, RoomHost}, EditOriginId) end, 1),
			[_] = wait_for_list(fun() -> eims_db:select_by_origin_id(chat, {AliceNode, Server}, OriginId) end, 1),
			[_] = PubSubArcPkts = wait_for_list(fun() -> eims_db:select_by_origin_id(chat, {AliceNode, Server}, OriginId) end, 1),
			[_] = PubSubArcPkts = wait_for_list(fun() -> eims_db:select_by_retract_id(chat, {AliceNode, Server}, EditOriginId) end, 1),
			EventPkt2 = #message{body = [#text{data = EditText}]} = eims:unwrap_mucsub_message(xmpp:decode(escalus:wait_for_stanza(Alice))),
			#origin_id{id = EditOriginId} = xmpp:get_subtag(EventPkt2, #origin_id{}),
			[_] = Mams = wait_for_list(fun() -> eims_db:select_by_origin_id(groupchat, {Room, RoomHost}, OriginId) end, 1),
			Mams = wait_for_list(fun() -> eims_db:select_by_retract_id(groupchat, {Room, RoomHost}, EditOriginId) end, 1),

			%% retract pubsub
			RetractPkt = xmpp:decode(escalus_stanza:groupchat_to(RoomJid, <<>>)),
			RetractPkt2 = RetractPkt#message{sub_els = [#hint{type = store}, #fasten_apply_to{id = EditOriginId, sub_els = [#retract_id{}]}, #origin_id{id = RetractId = <<"retract_1">>}]},
			send(Bob, RetractPkt2),
			escalus:assert(is_groupchat_message, [<<>>], escalus:wait_for_stanza(Bob)),
			[] = wait_for_list(fun() -> eims_db:select_by_origin_id(chat, {AliceNode, Server}, OriginId) end),
			[] = wait_for_list(fun() -> eims_db:select_by_origin_id(chat, {AliceNode, Server}, RetractId) end),
			[] = wait_for_list(fun() -> eims_db:select_by_retract_id(chat, {AliceNode, Server}, EditOriginId) end),
			[[] = wait_for_list(fun() -> eims_db:select_by_origin_id(groupchat, {Room, RoomHost}, Id) end) || Id <- [OriginId, RetractId]],
			ok
		end).

eims_upload_story(Config) ->
	RoomJid = do_test_room_jid(),
	_Nicks = [AliceNick, BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	Server = hd(ejabberd_option:hosts()),
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = _AliceJid} = Alice,
			#client{jid = _BobJid} = Bob) ->
			Clients = [Alice, Bob],
			do_enter_room(Alice, RoomJid, AliceNick),
			do_enter_room(Bob, RoomJid, BobNick),
			escalus:wait_for_stanzas(Alice, 2),
			escalus:wait_for_stanzas(Bob, 2),
			GetUrlTemplate =
				case mod_http_upload_opt:get_url(Server) of
					undefined -> mod_http_upload_opt:put_url(Server);
					GUrl -> GUrl
				end,
			UrlTemplateMap = #{scheme := Scheme} = uri_string:parse(binary:replace(GetUrlTemplate, <<"@HOST@">>, Server)),
			Port =
				case UrlTemplateMap of
					#{port := P} -> <<":", (integer_to_binary(P))/binary>>;
					_ -> <<>>
				end,
			InvalidUrl = <<Scheme/binary, "://", Server/binary, Port/binary, "/upload/alice/test2/test.txt">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?file_rm), " ", ?b(InvalidUrl)>>)),
			escalus:assert(is_groupchat_message, [<<"File not found">>], escalus:wait_for_stanza(Alice)),

			InvalidUrl2 = <<Scheme/binary, "://", Server/binary, Port/binary, "/upload/../../test.txt">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?file_rm), " ", ?b(InvalidUrl2)>>)),
			escalus:assert(is_groupchat_message, [<<"Invalid url">>], escalus:wait_for_stanza(Alice)),

			InvalidUrl3 = <<Scheme/binary, "://", Server/binary, Port/binary, "/upload/../../alice/test2/test.txt">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?file_rm), " ", ?b(InvalidUrl3)>>)),
			escalus:assert(is_groupchat_message, [<<"Invalid url">>], escalus:wait_for_stanza(Alice)),

			InvalidPortUrl = <<Scheme/binary, "://", Server/binary, ":9999/upload/alice/test/test.txt">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?file_rm), " ", ?b(InvalidPortUrl)>>)),
			escalus:assert(is_groupchat_message, [<<"Invalid url port">>], escalus:wait_for_stanza(Alice)),

			Url = <<Scheme/binary, "://", Server/binary, Port/binary, "/upload/alice/test/test.txt">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?file_rm), " ", ?b(Url)>>)),
			escalus:assert(is_groupchat_message, [<<"File successfully deleted">>], escalus:wait_for_stanza(Alice)),
			UploadDir = binary_to_list(mod_http_upload_opt:docroot(Server)),
			false = filelib:is_dir(filename:join(UploadDir, "alice/test")),

			send(Alice, escalus_stanza:groupchat_to(RoomJid, Url)),
			escalus:assert(is_groupchat_message, [Url], escalus:wait_for_stanza(Alice)),

			%% remove upload file by /del command
			do_create_upload_file(),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, <<"/", ?b(?del)>>)),
			escalus:assert(is_message, escalus:wait_for_stanza(Alice)),
			false = wait_for_result(fun() -> filelib:is_dir(filename:join(UploadDir, "alice/test")) end, false),

			%% remove upload file by retract message
			do_create_upload_file(),
			send(Alice, Pkt = escalus_stanza:groupchat_to(RoomJid, Url)),
			#origin_id{id = OriginId} = xmpp:get_subtag(xmpp:decode(escalus:wait_for_stanza(Alice)), #origin_id{}),
			RetractPkt = (xmpp:decode(Pkt))#message{body = [],
				sub_els = [#fasten_apply_to{id = OriginId, sub_els = [#retract_id{}]}, #hint{type = store}]},
			send(Alice, RetractPkt),
			escalus:assert(is_message, escalus:wait_for_stanza(Alice)),
			false = wait_for_result(fun() -> filelib:is_dir(filename:join(UploadDir, "alice/test")) end, false),

			%% remove upload file with #messsge_upload{} subtag by retract message
			do_create_upload_file(),
			Pkt2 = xmpp:set_subtag(xmpp:decode(escalus_stanza:groupchat_to(RoomJid, <<"url">>)),
				MsgUpload = #message_upload{body = [#message_upload_body{url = Url}]}),
			send(Alice, Pkt2),
			#origin_id{id = OriginId2} = xmpp:get_subtag(ReceivePkt = xmpp:decode(escalus:wait_for_stanza(Alice)), #origin_id{}),
			MsgUpload = xmpp:get_subtag(ReceivePkt, #message_upload{}),
			RetractPkt2 = (xmpp:decode(Pkt))#message{body = [],
				sub_els = [#fasten_apply_to{id = OriginId2, sub_els = [#retract_id{}]}, #hint{type = store}]},
			send(Alice, RetractPkt2),
			escalus:assert(is_message, escalus:wait_for_stanza(Alice)),
			false = wait_for_result(fun() -> filelib:is_dir(filename:join(UploadDir, "alice/test")) end, false),

			%% Alice removes upload file by moderate retract message
			do_create_upload_file(),
			send(Bob, Pkt2),
			#mam_archived{id = MamId} = xmpp:get_subtag(ReceivePkt2 = xmpp:decode(escalus:wait_for_stanza(Alice)), #mam_archived{}),
			MsgUpload = xmpp:get_subtag(ReceivePkt2, #message_upload{}),
			ModeratePkt = #iq{type = set, to = jid:decode(RoomJid),
				sub_els = [#fasten_apply_to{id = MamId, sub_els = [#message_moderate_21{retract = #retract_id{}}]}]},
			send(Alice, ModeratePkt),
			escalus:assert(is_iq, escalus:wait_for_stanza(Alice)),
			false = wait_for_result(fun() -> filelib:is_dir(filename:join(UploadDir, "alice/test")) end, false),

			escalus:wait_for_stanzas(Bob, 8),

			%% Bob trys to remove Alice upload file
			do_create_upload_file(),
			send(Bob, BobPkt = escalus_stanza:groupchat_to(RoomJid, Url)),
			#origin_id{id = BobOriginId} = xmpp:get_subtag(xmpp:decode(escalus:wait_for_stanza(Bob)), #origin_id{}),
			BobRetractPkt = (xmpp:decode(BobPkt))#message{body = [],
				sub_els = [#fasten_apply_to{id = BobOriginId, sub_els = [#retract_id{}]}, #hint{type = store}]},
			send(Bob, BobRetractPkt),
			[escalus:wait_for_stanza(Client) || Client <- Clients],
			true = filelib:is_dir(filename:join(UploadDir, "alice/test")),

			%% remove upload file by p2p retract
			do_create_upload_file(),
			AlicePkt = #message{sub_els = AliceEls} = xmpp:decode(escalus_stanza:chat_to_short_jid(Bob, Url)),
			send(Alice, AlicePkt#message{sub_els = [#receipt_request{}, #origin_id{id = OId = <<"1">>} | AliceEls]}),

			escalus:assert(is_chat_message, [Url], AlicePkt2 = escalus:wait_for_stanza(Bob)),
			#origin_id{id = OId} = xmpp:get_subtag(xmpp:decode(AlicePkt2), #origin_id{}),

			AliceRetractPkt = xmpp:set_subtag(xmpp:set_subtag(AlicePkt#message{body = [#text{data = <<>>}]},
				#fasten_apply_to{id = OId, sub_els = [#retract_id{}]}), #hint{type = store}),
			send(Alice, AliceRetractPkt),
			#fasten_apply_to{id = OId, sub_els = [#retract_id{}]} = xmpp:get_subtag(xmpp:decode(escalus:wait_for_stanza(Bob)), #fasten_apply_to{}),
			false = wait_for_result(fun() -> filelib:is_dir(filename:join(UploadDir, "alice/test")) end, false),
			ok
		end).

search_story(Config) ->
	RoomJid = do_test_room_jid(),
	Nicks = [AliceNick, _BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	[Room, Server] = binary:split(RoomJid, <<"@">>),
%%	Host = escalus_config:get_ct(ejabberd_domain),
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = AliceJid} = Alice,
			#client{jid = BobJid} = Bob) ->
			UserNodes = [_AliceNode, _BobNode] = [hd(binary:split(J, <<"@">>)) || J <- [AliceJid, BobJid]],
			Users = lists:zip3(Clients = [Alice, Bob], Nicks, UserNodes),
			[do_enter_room(Client, RoomJid, Nick) || {Client, Nick, _} <- Users],
			[escalus:wait_for_stanzas(Client, 2) || Client <- Clients],
			Text = <<"Hello, all!">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, Text)),
			[escalus:assert(is_groupchat_message, [Text], escalus:wait_for_stanza(Client)) || Client <- Clients],
			IQ = #iq{type = set, to = jid:make(Room, Server),
				sub_els = [Query = #mam_query{xmlns = ?NS_MAM_2, id = eims:gen_uuid(),
					xdata = X = #xdata{type = submit,
						fields = Fields = [#xdata_field{type = hidden, var = <<"FORM_TYPE">>, values = [<<"urn:xmpp:mam:2">>]}
						]},
					rsm = #rsm_set{before = <<"">>, max = 999}}
				]},
			send(Alice, IQ),
			escalus:assert(is_message, escalus:wait_for_stanza(Alice)),
			IqFields = #iq{type = get, sub_els = [#mam_query{xmlns = <<"urn:xmpp:mam:2">>}]},
			send(Alice, IqFields),
			escalus:assert(is_iq_result, escalus:wait_for_stanza(Alice)),
			escalus:wait_for_stanzas(Alice, 1),
			IQ2 = IQ#iq{sub_els = [Query#mam_query{xdata =
			X#xdata{fields = Fields ++
			[#xdata_field{var = <<"with_nick">>, values = [AliceNick]},
				#xdata_field{var = <<"start">>, values = [<<"2020-06-07T00:00:00Z">>]}]}}]}, %% before "start" value
			send(Alice, IQ2),
			escalus:assert(is_message, SearchPkt = escalus:wait_for_stanza(Alice)),
			#message{sub_els = [#mam_result{sub_els = [#forwarded{sub_els = [Pkt]}]}]} = xmpp:decode(SearchPkt),
			escalus:assert(is_groupchat_message, [Text], Pkt),
			#iq{type = result, sub_els = [#mam_fin{rsm = #rsm_set{count = 1}}]} = xmpp:decode(escalus:wait_for_stanza(Alice)),

			IQ3 = IQ#iq{sub_els = [Query#mam_query{xdata =
			X#xdata{fields = Fields ++
			[#xdata_field{var = <<"with_nick">>, values = [AliceNick]},
				#xdata_field{var = <<"start">>, values = [<<"2043-06-07T00:00:00Z">>]}]}}]}, %% after "start" value
			send(Alice, IQ3),
			#iq{type = result, sub_els = [#mam_fin{rsm = #rsm_set{count = 0}}]} = xmpp:decode(escalus:wait_for_stanza(Alice)),

			%% full-text search
			IQ4 = IQ#iq{sub_els = [Query#mam_query{xdata =
			X#xdata{fields = Fields ++
			[#xdata_field{var = <<"withtext">>, values = [<<"hello">>]},
				#xdata_field{var = <<"start">>, values = [<<"2013-06-07T00:00:00Z">>]}]}}]}, %% after "start" value
			send(Alice, IQ4),
			escalus:assert(is_message, SearchPkt4 = escalus:wait_for_stanza(Alice)),
			#message{sub_els = [#mam_result{sub_els = [#forwarded{sub_els = [Pkt4]}]}]} = xmpp:decode(SearchPkt4),
			escalus:assert(is_groupchat_message, [Text], Pkt4),
			#iq{type = result, sub_els = [#mam_fin{rsm = #rsm_set{count = 1}}]} = xmpp:decode(escalus:wait_for_stanza(Alice)),
			ok
		end).


flood_story(Config) ->
	RoomJid = do_test_room_jid(),
	Nicks = [_AliceNick, _BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = AliceJid} = Alice,
			#client{jid = BobJid} = Bob) ->
			UserNodes = [_AliceNode, _BobNode] = [hd(binary:split(J, <<"@">>)) || J <- [AliceJid, BobJid]],
			Users = lists:zip3(Clients = [Alice, Bob], Nicks, UserNodes),
			[do_enter_room(Client, RoomJid, Nick) || {Client, Nick, _} <- Users],
			[escalus:wait_for_stanzas(Client, 2) || Client <- Clients],
			Text = <<"Hello, all!">>,
			send(Alice, escalus_stanza:groupchat_to(RoomJid, Text)),
			[escalus:assert(is_groupchat_message, [Text], escalus:wait_for_stanza(Client)) || Client <- Clients],
			Time = mod_mam:make_id(),
			send(Alice, escalus_stanza:groupchat_to(RoomJid, Text)),
			[escalus:assert(is_groupchat_message, [Text], escalus:wait_for_stanza(Client)) || Client <- Clients],
			?a(mod_mam:make_id() - Time < 300000),

			send(Bob, escalus_stanza:groupchat_to(RoomJid, Text)),
			[escalus:assert(is_groupchat_message, [Text], escalus:wait_for_stanza(Client)) || Client <- Clients],

			Time2 = mod_mam:make_id(),
			send(Bob, escalus_stanza:groupchat_to(RoomJid, Text)),
			[escalus:assert(is_groupchat_message, [Text], escalus:wait_for_stanza(Client)) || Client <- Clients],
			?a(mod_mam:make_id() - Time2 > 800000),
			ok
		end).

%% OAUTH
clrf_oauth_story(_Config) ->
	[AliceNode, Host, AlicePwd] = [escalus_config:get_ct({escalus_users, alice, K}) || K <- [username, server, password]],
	Uri = #{scheme => "http", host => Host, path => "oauth/authorization_token", port => 5280},
	Injection = "http://www.example.com/example.php?id="
	"\r\nContent-Length:%200\r\n\r\n HTTP/1.1%20200%20OK\r\nContent-Type:%20text/html\r\n"
	"Content-Length:%2025\r\n\r\n %3Cscript%3Ealert(1)%3C/script%3E",
	Query = [{"username", <<AliceNode/binary, "@", Host/binary>>},
		{"password", AlicePwd},
		{"response_type", "token"},
		{"scope", "get_roster+sasl_auth"}],
	{ok, {{_, 400, "Bad Request"}, _, _}} = %% redirect injection
		httpc:request(post, {uri_string:normalize(Uri),
			[], "application/x-www-form-urlencoded", uri_string:compose_query([{"redirect_uri", Injection}, {"state", "1"} | Query])}, [], []),
	{ok, {{_, 400, "Bad Request"}, _, _}} = %% state injection
		httpc:request(post, {uri_string:normalize(Uri),
			[], "application/x-www-form-urlencoded", uri_string:compose_query([{"state", Injection} | Query])}, [], []),
	ok.

-record(format, {key = [], name = [], value = []}).

format_story(Config) ->
	{Formatted, Entities} = eims_format:reply_to_text(summary, do_summary()),
	FormattedBinary = iolist_to_binary(Formatted),
	ct:print(FormattedBinary),
	ct:print("~p", [Entities]),
	do_check_format(FormattedBinary, summary, do_summary(), Entities),
	Config.

%% Rooms with restrictions
rfq_story(Config) ->
	RfqRoom = escalus_config:get_ct({eims_rooms, eims_rfq, name}),
	_Nicks = [AliceNick, BobNick] = [escalus_config:get_ct({escalus_users, U, nick}) || U <- [alice, bob]],
	MucHost = eims:muc_host(),
	escalus:story(Config, [{alice, 1}, {bob, 1}],
		fun(#client{jid = _AliceJid} = Alice,
			#client{jid = _BobJid} = Bob) ->
			Clients = [Alice, Bob],
			do_enter_room(Alice, jid:encode({RfqRoom, MucHost, <<>>}), AliceNick),
			do_enter_room(Bob, jid:encode({RfqRoom, MucHost, <<>>}), BobNick),
			[escalus:wait_for_stanzas(Client, 2) || Client <- Clients],

			[{_, AliceNick, "moderator"}, {_, BobNick, "visitor"}] = mod_muc_admin:get_room_occupants(RfqRoom, MucHost),

			BobPkt = #message{type = chat, to = RfqJID = jid:make(RfqRoom, MucHost, AliceNick), body = [#text{data = BobMsg = <<"Hello, Alice!">>}],
				sub_els = [#origin_id{id = OriginId = eims:gen_uuid()}]},
			RfqJid = jid:encode(BareRfqJid = jid:remove_resource(RfqJID)),
			send(Bob, BobPkt),
			escalus:assert(is_chat_message, [BobMsg], escalus:wait_for_stanza(Alice)),
			send(Bob, BobPkt#message{type = groupchat, to = jid:make(RfqRoom, MucHost)}),
			ErrorPkt = #message{type = error} = xmpp:decode(escalus:wait_for_stanza(Bob)),
			#stanza_error{type = auth, reason = forbidden, text = [#text{data = <<"Visitors are not allowed to send messages to all occupants">>}]} =
				xmpp:get_subtag(ErrorPkt, #stanza_error{}),

			[_, _] = eims_sql:select_all_by_retract_id(OriginId),
			send(Alice, escalus_stanza:groupchat_to(RfqJid, <<"/", ?b(?purge), " ", BobNick/binary, " kick">>)),
			[RetractPkt,
				#presence{type = unavailable},
				#message{body = [#text{data = <<"whale.bob messages have been deleted successfully">>}]}] =
					[xmpp:decode(P) || P <- escalus:wait_for_stanzas(Alice, 3)],
			#fasten_apply_to{sub_els = [#retract_id{}]} = xmpp:get_subtag(RetractPkt, #fasten_apply_to{}),
			[#presence{type = unavailable},
				#presence{type = unavailable}] = [xmpp:decode(P) || P <- escalus:wait_for_stanzas(Bob, 2)],

			{error, not_found} = eims_sql:select_all_by_retract_id(OriginId),
			ok
		end),
	Config.

do_check_format(FormattedBinary, RequestName, Map, Entities) ->
	{SummaryList, _} = eims_format:fill_format_list(RequestName, Map),
	[ct:print(binary:part(FormattedBinary, Offset, Length)) || #message_entity{offset = Offset, length = Length, type = _Type} <- Entities],

	Fun =
		fun Fun(List, Es) -> %% recursive check of entities
			lists:foldl(
				fun(#format{name = Name, value = {[#format{} | _] = SubList, _}}, Es2) ->
						RmEs = [_] = [E || #message_entity{offset = Offset, length = Length, type = Type} = E <- Es2,
							iolist_to_binary(string:strip(binary_to_list(binary:part(FormattedBinary, Offset, Length)), right)) == Name
								andalso Type == eims_format:entity_type(key)],
						Fun(SubList, lists:subtract(Es2, RmEs));
					(#format{name = Name, value = Value}, Es2) ->
						FoundEs = [_ | _] = [E || #message_entity{offset = Offset, length = Length, type = Type} = E <- Es2,
							iolist_to_binary(string:strip(binary_to_list(binary:part(FormattedBinary, Offset, Length)), right)) == Name
								andalso Type == eims_format:entity_type(key)],
						RmEs = [_, _] =
							catch [begin
								       E2 = #message_entity{offset = ValueOffset, length = ValueLength, type = ValueType} =
									       lists:keyfind(Offset + Length, #message_entity.offset, Es2),
								       ValueType = eims_format:entity_type(value),
								       V = iolist_to_binary(eims_format:format(Value)),
								       case binary:part(FormattedBinary, ValueOffset, ValueLength) of
									       V -> throw([E, E2]);
									       V2 -> ct:comment("~p /= ~p", [V, V2]), []
								       end
							       end || #message_entity{offset = Offset, length = Length, type = Type} = E <- FoundEs],
						lists:subtract(Es2, RmEs)
				end, Es, List)
		end,
	Header = eims_format:header(RequestName),
	HeaderEntity = eims_format:entity(header, Header),
	[HeaderEntity] = Fun(SummaryList, Entities).

do_summary() ->
	#{<<"options_gamma">> => 0.0, <<"equity">> => 0.0,
		<<"available_withdrawal_funds">> => 0.0,
		<<"creation_timestamp">> => 1671568818192,
		<<"margin_balance">> => 0.0, <<"total_pl">> => 0.0,
		<<"portfolio_margining_enabled">> => false,
		<<"projected_delta_total">> => 0.0,
		<<"spot_reserve">> => 0.0, <<"available_funds">> => 0.0,
		<<"email">> => <<"cryoflamer@ukr.net">>,
		<<"projected_initial_margin">> => 0.0,
		<<"estimated_liquidation_ratio_map">> => #{},
		<<"balance">> => 0.0, <<"options_pl">> => 0.0,
		<<"options_delta">> => 0.0,
		<<"interuser_transfers_enabled">> => false,
		<<"username">> => <<"cryoflamer2">>,
		<<"options_theta">> => 0.0, <<"referrer_id">> => null,
		<<"options_session_upl">> => 0.0,
		<<"futures_session_upl">> => 0.0,
		<<"system_name">> => <<"cryoflamer2">>,
		<<"session_rpl">> => 0.0, <<"options_vega">> => 0.0,
		<<"projected_maintenance_margin">> => 0.0,
		<<"security_keys_enabled">> => false,
		<<"options_value">> => 0.0, <<"currency">> => <<"BTC">>,
		<<"futures_pl">> => 0.0, <<"initial_margin">> => 0.0,
		<<"type">> => <<"main">>,
		<<"limits">> =>
			#{<<"matching_engine">> =>
				#{<<"burst">> => 20, <<"rate">> => 5},
			 <<"non_matching_engine">> =>
				#{<<"burst">> => 100, <<"rate">> => 20}},
		<<"estimated_liquidation_ratio">> => 0.0,
		<<"fee_balance">> => 0.0, <<"session_upl">> => 0.0,
		<<"delta_total_map">> => #{},
		<<"futures_session_rpl">> => 0.0,
		<<"options_session_rpl">> => 0.0, <<"id">> => 47973,
		<<"delta_total">> => 0.0, <<"maintenance_margin">> => 0.0}.

do_create_upload_file() ->
	Host = hd(ejabberd_option:hosts()),
	UploadDir = binary_to_list(mod_http_upload_opt:docroot(Host)),
	[file:make_dir(filename:join(UploadDir, Dir)) || Dir <- ["alice", "alice/test"]],
	FileName = filename:join(UploadDir, "alice/test/test.txt"),
	ok = file:write_file(FileName, <<"test">>),
	FileName.

%% This function is a version of escalus_client:stop/2
%% that ensures that c2s process is dead.
%% This allows to avoid race conditions.
do_logout_user(Config, User) ->
	Resource = escalus_client:resource(User),
	Username = escalus_client:username(User),
	Server = escalus_client:server(User),
	Result = ejabberd_sm:get_session_pid(Username, Server, Resource),
	case Result of
		none ->
			%% This case can be a side effect of some error, you should
			%% check your test when you see the message.
			ct:pal("issue=user_not_registered jid=~ts@~ts/~ts",
				[Username, Server, Resource]),
			escalus_client:stop(Config, User);
		Pid when is_pid(Pid) ->
			MonitorRef = erlang:monitor(process, Pid),
			escalus_client:stop(Config, User),
			%% Wait for pid to die
			receive
				{'DOWN', MonitorRef, _, _, _} ->
					ok
			after 10000 ->
				ct:pal("issue=c2s_still_alive "
				"jid=~ts@~ts/~ts pid=~p",
					[Username, Server, Resource, Pid]),
				ct:fail({logout_user_failed, {Username, Resource, Pid}})
			end
	end.

do_env_vars() ->
	[].

%% Help functions TODO move to escalus_stanza module
do_enter_groupchat(#client{jid = FromJid}, RoomJid, Nick) ->
	#xmlel{name = <<"presence">>,
		attrs = [{<<"from">>, FromJid}, {<<"to">>, <<RoomJid/binary, "/", Nick/binary>>}],
		children = [#xmlel{name = <<"x">>, attrs = [{<<"xmlns">>, ?NS_MUC}]}]}.

do_test_room_jid() ->
	do_room_jid(eims_test).

do_room_jid(Room) ->
	RoomName = escalus_config:get_ct({eims_rooms, Room, name}),
	RoomHost = escalus_ct:get_config(room_host),
	<<RoomName/binary, "@", RoomHost/binary>>.

do_enter_room(Client, RoomJid, Nick) ->
	send(Client, do_enter_groupchat(Client, RoomJid, Nick)),
	escalus_client:wait_for_stanzas(Client, 2). %% Client wait for 2 presences from ChatRoom

do_match_rule(<<"localhost">>, eims_admin, #{usr := {<<"alice">>, <<"localhost">>, <<>>}}) ->
	allow;
do_match_rule(Server, configure, U) ->
	meck:passthrough([Server, eims_admin, U]);
do_match_rule(Host, Access, Match) ->
	meck:passthrough([Host, Access, Match]).

do_send_fun({Jid, OldData}, Interval, Pid) ->
	fun(Data) ->
		NewData = Data + 1,
		OldData = eims:get_tokens(Jid),
		{TRef, _} = eims:send_delay_check({Jid, NewData}, do_send_fun({Jid, NewData}, Interval, Pid), Interval),
		Pid ! {sys_time, calendar:local_time(), NewData, TRef}
	end.
do_receive_delay_msg(BeginSec) ->
	receive
		{sys_time, Time, Data, TRef} when Data > 21 ->
			ct:comment("data: ~p", [Data]),
			Sec = calendar:datetime_to_gregorian_seconds(Time),
			?assert(Sec - BeginSec =< 2),
			erlang:cancel_timer(TRef);
		{sys_time, _Time, Data, _TRef} ->
			ct:comment("data: ~p", [Data]),
			do_receive_delay_msg(BeginSec)
	after 2000 -> ?assert(false)
	end.

do_request(Method, Request, HTTPOptions, []) ->
	case catch do_request(uri_string:parse(element(1, Request)), element(2, Request)) of
		{'EXIT', _} -> meck:passthrough([Method, Request, HTTPOptions, []]);
		Res -> Res
	end.

%% S basic Reqiests to integrated service
do_request(#{path := "/api/v2/private/get_account_summary", query := [{"currency", Currency}, {"extended", "true"}]}, _Headers)
	when Currency == "BTC"; Currency == "ETH" ->
	Body = jiffy:encode(#{<<"result">> =>
	#{<<"email">> => <<"bob@fakeemail.com">>,
		<<"currency">> => list_to_binary(Currency)}}),
	{ok, {{[], 200, []}, [], Body}};
do_request(#{path := "/api/v2/private/get_account_summary", query := Query} = MapURI, Headers) ->
	do_request(MapURI#{query => uri_string:dissect_query(Query)}, Headers);
do_request(#{path := "/api/v2/public/auth", query := "grant_type=" ++ _}, _Headers) ->
	HttpCode = application:get_env(ejabberd, refresh_token_http_code, 200),
	{ok, {{[], HttpCode, []}, [], do_get_tokens_body(HttpCode)}};
do_request(#{path := "/api/v2/public/auth"}, _Headers) ->
	HttpCode = application:get_env(ejabberd, refresh_token_http_code, 200),
	{ok, {{[], HttpCode, []}, [], do_get_tokens_body(HttpCode)}};
do_request(#{path := "/api/v2/private/chat_get_account_summary"}, [{"Authorization", "bearer " ++ (UserNode = "whale.clara")}]) ->
	Body = #{<<"result">> := Result} = do_get_eims_storage(UserNode),
	BobResult = Result#{<<"main_account_id">> := 9999, <<"id">> := 8888},
  {ok, {{[], 200, []}, [], jiffy:encode(Body#{<<"result">> := BobResult})}};
do_request(#{path := "/api/v2/private/chat_get_account_summary"}, [{"Authorization", "bearer " ++ (UserNode = "whale.bob")}]) ->
	Body = #{<<"result">> := Result} = do_get_eims_storage(UserNode),
	BobResult = Result#{<<"main_account_id">> := 9999, <<"id">> := 9999},
	{ok, {{[], 200, []}, [], jiffy:encode(Body#{<<"result">> := BobResult})}};
do_request(#{path := "/api/v2/private/chat_get_account_summary"}, [{"Authorization", "bearer " ++ UserNode}]) ->
	Body = jiffy:encode(do_get_eims_storage(UserNode)),
	{ok, {{[], 200, []}, [], Body}}.

do_get_eims_storage("whale." ++ UserStr = UserNode) ->
	User = list_to_binary(UserStr),
	UserNodeBin = list_to_binary(UserNode),
%%	[<<"whale">>, User] = binary:split(UserNodeBin = list_to_binary(UserNode), <<".">>),
	Id = rand:uniform(1000),
	#{<<"result">> =>
	#{<<"system_name">> => User,
		<<"jid_node">> => UserNodeBin,
		<<"nick">> => UserNodeBin,
		<<"email">> => <<User/binary, "@fakemail.com">>,
		<<"main_account_id">> => Id,
		<<"id">> => Id,
		<<"main_system_name">> => User,
		<<"main_email">> => <<User/binary, "@fakemail.com">>,
		<<"roles">> => <<"role1, role2">>}};
do_get_eims_storage(_Token) ->
	User = UserNodeBin = <<"alice">>,
	Id = rand:uniform(1000),
	#{<<"result">> =>
	#{<<"system_name">> => User,
		<<"jid_node">> => UserNodeBin,
		<<"nick">> => UserNodeBin,
		<<"email">> => <<User/binary, "@fakemail.com">>,
		<<"main_account_id">> => Id,
		<<"id">> => Id,
		<<"main_system_name">> => User,
		<<"main_email">> => <<User/binary, "@fakemail.com">>,
		<<"roles">> => <<"role1, role2">>}}.

do_get_tokens_body(400) ->
	jiffy:encode(
		#{<<"error">> =>
		#{<<"data">> => #{<<"param">> => <<"refresh_token">>,
			<<"reason">> => <<"wrong format">>},
			<<"message">> => <<"Token refresh failed">>}});
do_get_tokens_body(200) ->
	jiffy:encode(#{<<"result">> =>
	#{<<"access_token">> => integer_to_binary(rand:uniform(1000)),
		<<"refresh_token">> => integer_to_binary(rand:uniform(1000))}}).

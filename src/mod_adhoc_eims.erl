-module(mod_adhoc_eims).
-compile(export_all).

-protocol({xep, 50, '1.2', '1.1.0', "complete", ""}).

-behaviour(gen_mod).

-include("logger.hrl").
-include_lib("ejabberd_web_admin.hrl").
-include_lib("xmpp/include/xmpp.hrl").
-include("eims.hrl").
-include_lib("translate.hrl").

-export([
    start/2,
    stop/1,
    depends/2,
    mod_doc/0,
    mod_options/1,

    list_banned/0,
    banned_jids/0,
    insert_banned/1,
    remove_banned/1,
    is_banned/1,
    generate_ban_form/0,
    items/4,
    check_access/4,
    unban_command/2]).

-define(ITEMS, [?NS_NODE_BAN]).
-define(CMDS, [check_access]).

%% XXX: default implementation is going to be in English.
-define(DEFAULT_LANG, <<"en">>).

-define(NS_ADMINX(Sub),
    <<(?NS_ADMIN)/binary, "#", Sub/binary>>).

-define(NS_ADMINL(Sub),
    [<<"http:">>, <<"jabber.org">>, <<"protocol">>,
        <<"admin">>, Sub]).

-spec tokenize(binary()) -> [binary()].
tokenize(Node) -> str:tokens(Node, <<"/#">>).

-define(TVFIELD(Type, Var, Val),
    #xdata_field{type = Type, var = Var, values = [Val]}).

-define(HFIELD(),
    ?TVFIELD(hidden, <<"FORM_TYPE">>, (?NS_ADMIN))).

-define(TLFIELD(Type, Label, Var),
    #xdata_field{type = Type, label = tr(Lang, Label), var = Var}).


start(Host, _Opts) ->
    ejabberd_hooks:add(adhoc_local_items, Host, ?MODULE, items, 100),
    lists:map(fun(Cmd) ->
        ejabberd_hooks:add(adhoc_local_commands, Host, ?MODULE, Cmd, 100)
    end, ?CMDS),
    ok.

stop(Host) ->
    lists:map(fun(Cmd) ->
        ejabberd_hooks:delete(adhoc_local_commands, Host, ?MODULE, Cmd, 100)
    end, ?CMDS),
    ejabberd_hooks:delete(adhoc_local_items, Host, ?MODULE, items, 100),
    ok.

depends(_Host, _Opts) ->
    [{mod_adhoc, hard}].

mod_options(_Host) ->
    [].

mod_doc() ->
    #{desc => "Implements EIMS commands", opts => []}.

-spec search_running_node(binary()) -> false | node().
search_running_node(SNode) ->
    search_running_node(SNode,
        mnesia:system_info(running_db_nodes)).

-spec search_running_node(binary(), [node()]) -> false | node().
search_running_node(_, []) -> false;
search_running_node(SNode, [Node | Nodes]) ->
    case atom_to_binary(Node, utf8) of
        SNode -> Node;
        _ -> search_running_node(SNode, Nodes)
    end.


-spec adhoc_local_commands(jid(), jid(), adhoc_command()) -> adhoc_command() | {error, stanza_error()}.
adhoc_local_commands(From,
    #jid{lserver = LServer} = _To,
    #adhoc_command{lang = Lang, node = Node,
        sid = SessionID, action = Action,
        xdata = XData} = Request) ->
    LNode = tokenize(Node),
    ActionIsExecute = Action == execute orelse Action == complete,
    if Action == cancel ->
        #adhoc_command{status = canceled, lang = Lang,
            node = Node, sid = SessionID};
        XData == undefined, ActionIsExecute ->
            case get_form(LServer, LNode, Lang) of
                {result, Form} ->
                    xmpp_util:make_adhoc_response(
                        Request,
                        #adhoc_command{status = executing, xdata = Form});
                {result, Status, Form} ->
                    xmpp_util:make_adhoc_response(
                        Request,
                        #adhoc_command{status = Status, xdata = Form});
                {error, Error} -> {error, Error}
            end;
        XData /= undefined, ActionIsExecute ->
            case set_form(From, LServer, LNode, Lang, XData) of
                {result, Res} ->
                    xmpp_util:make_adhoc_response(
                        Request,
                        #adhoc_command{xdata = Res, status = completed});
                %%{'EXIT', _} -> {error, xmpp:err_bad_request()};
                {error, Error} -> {error, Error}
            end;
        true ->
            {error, xmpp:err_bad_request(?T("Unexpected action"), Lang)}
    end.



-spec get_permission_level(jid()) -> global | vhost.
get_permission_level(JID) ->
    case acl:match_rule(global, configure, JID) of
        allow -> global;
        deny -> vhost
    end.

set_form(#jid{luser = U, lserver = S} = From, Host, ?NS_ADMINL(<<"add-user">>), _Lang,
    XData) ->
    %ct:print("XData ~p", [XData]),
    AccountString = get_value(<<"accountjid">>, XData),
    Password = get_value(<<"password">>, XData),
    Password = get_value(<<"password-verify">>, XData),
    AccountJID = jid:decode(AccountString),
    User = AccountJID#jid.luser,
    Server = AccountJID#jid.lserver,
    Admin = eims:get_permission_level({U, S}, [<<"admin">>]),
    Roles = case get_values(<<"Roles">>, XData) of
                               []-> [<<"none">>];
                _ when Admin==false -> [<<"none">>];
                             R -> R end,
    Nick = case get_values(<<"Nick">>, XData) of [] -> User; [N] -> N end,
    true = lists:member(Server, ejabberd_option:hosts()),
    true = Server == Host orelse
        get_permission_level(From) == global,
    SysName = eims:string_to_lower(Nick),
    case eims:get_storage_by_field(SysName, #eims_storage.system_name) of
        #eims_storage{} ->
              {error, xmpp:err_conflict(<<"Nick ", Nick/binary, " is reserved">>, <<"en-US">>)};
          _ ->
               case ejabberd_auth:try_register(User, Server, Password) of
                   ok -> {_PrivateData, UStorage} = eims:gen_summary(Nick, User),
                          ok = mnesia:dirty_write(UStorage#eims_storage{roles = Roles}),
                          {result, undefined};
                   {error, exists} -> {error, xmpp:err_conflict(<<"User ", Nick/binary, " exists">>, <<"English">>)};
                   {error, not_allowed} -> {error, xmpp:err_not_allowed()}
               end
    end;
set_form(From, Host, ?NS_ADMINL(<<"delete-user">>),
    _Lang, XData) ->
    AccountStringList = get_values(<<"accountjid">>,
        XData),
    [_ | _] = AccountStringList,
    ASL2 = lists:map(fun (AccountString) ->
        JID = jid:decode(AccountString),
        User = JID#jid.luser,
        Server = JID#jid.lserver,
        true = Server == Host orelse
            get_permission_level(From) == global,
        true = ejabberd_auth:user_exists(User, Server),
        case mnesia:dirty_read(eims_storage, {User, Server}) of
            [#eims_storage{} = FRecord| _] = UStors->
                     ok = mnesia:dirty_write(FRecord#eims_storage{roles = [<<"deleted">>]}),
                    [ok = mnesia:dirty_delete_object(UStor) || UStor <- UStors--[FRecord]];
            _ -> ok
        end,
        {User, Server}
                     end,
        AccountStringList),
    [ejabberd_auth:remove_user(User, Server)
        || {User, Server} <- ASL2],
    {result, undefined};
set_form(From, Host,
    ?NS_ADMINL(<<"change-user-password">>), _Lang, XData) ->
    AccountString = get_value(<<"accountjid">>, XData),
    Password = get_value(<<"password">>, XData),
    JID = jid:decode(AccountString),
    User = JID#jid.luser,
    Server = JID#jid.lserver,
    true = Server == Host orelse
        get_permission_level(From) == global,
    true = ejabberd_auth:user_exists(User, Server),
    ejabberd_auth:set_password(User, Server, Password),
    {result, undefined};
set_form(_From, _Host, _, _Lang, _XData) ->
    {error, xmpp:err_service_unavailable()}.


-spec get_value(binary(), xdata()) -> binary().
get_value(Field, XData) ->
    hd(get_values(Field, XData)).

-spec get_values(binary(), xdata()) -> [binary()].
get_values(Field, XData) ->
    xmpp_util:get_xdata_values(Field, XData).

string_to_jid(JID) when is_binary(JID) ->
    jid:from_string(JID).

-spec items(mod_disco:items_acc(), jid(), jid(), binary()) -> {result, [disco_item()]}.
items({result, I}, From, #jid{server = Server} = _To, _Lang) ->
    {result, I ++ get_items(From, Server)};
items(_Acc, From, #jid{server = Server} = _To, _Lang) ->
    {result, get_items(From, Server)}.

-spec check_access(adhoc_command(), jid(), jid(), adhoc_command()) ->
    adhoc_command() | {error, stanza_error()}.
check_access(Acc, #jid{luser = U, lserver = S}, #jid{lserver = Server} = To,
    #adhoc_command{node = <<"user">>} = Request) ->
    ct:print("check_access!!!!! ~p", [{U, S}]),
    case get_user(U,S) of
        #{} = Res ->
            xmpp_util:make_adhoc_response(
                Request,
                #adhoc_command{
                    xdata = #xdata{
                        type = form,
                        fields = [?HFIELD(),
                            #xdata_field{
                                type = 'text-single',
                                label = <<"User info">>,
                                var = <<"json">>,
                                values = [jiffy:encode(Res)]
                            }]},
                    status = completed,
                    node = Request#adhoc_command.node,
                    sid = Request#adhoc_command.sid
                }
            );
        Err ->
            Err
    end;
check_access(Acc, #jid{luser = U, lserver = S} = From, #jid{lserver = Server} = To,
    #adhoc_command{node = Node} = Request) ->
    %ct:print("Command!!!!! ~p", [eims:check_role({U, S}, [<<"admin">>, <<"user">>])]),
    case eims:get_permission_level({U, S}, [<<"admin">>, <<"user">>]) of
        true  -> cmd(Acc, Request, From, To);
        _ -> xmpp:err_forbidden(<<"Command disallowed for you">>, ?DEFAULT_LANG)
    end.

exec_local_cmd(From, To, Cmd, Acl)->
    case Acl of
        true -> case adhoc_local_commands(From, To, Cmd) of
                 #adhoc_command{} =Command -> Command;
                 Err -> Err end;
        false -> xmpp:err_forbidden(<<"Command disallowed for you">>, ?DEFAULT_LANG)
end.


%%cmd(_Acc, #adhoc_command{node = Node , xdata = XData, action = Action} = Request, #jid{luser = U, lserver = S} =From, To)
%%    when Node =:= <<"delete-user">>->
%%    Allow = eims:get_permission_level({U, S}, [<<"admin">>]),
%%    exec_local_cmd(From, To, Request#adhoc_command{node = ?NS_ADMINX(Node), action = Action}, Allow);

cmd(_Acc, #adhoc_command{node = Node , xdata = XData, action = Action} = Request, #jid{luser = U, lserver = S} =From, To)
    when Node =:= <<"add-user">> orelse Node =:= <<"delete-user">> ->
    Roles = case Node of
       <<"add-user">> -> [<<"admin">>];
       _ -> [<<"admin">>, <<"user">>]
    end,
    Allow = eims:get_permission_level({U, S}, Roles),
    exec_local_cmd(From, To, Request#adhoc_command{node = ?NS_ADMINX(Node), action = Action}, Allow);

cmd(_Acc, #adhoc_command{node = <<"change-user-password">> = Node , xdata = XData, action = Action} = Request,
    #jid{luser = U, lserver = S} =From, To)  ->
    Manager = eims:get_permission_level({U, S}, [<<"user">>]),
    Allow = case eims:get_permission_level({U, S}, [<<"admin">>]) of
                true -> true;
                _ when Manager -> JID = jid:decode(get_value(<<"accountjid">>, XData)),
                                  JID#jid.luser==U;
                _  -> false
    end,
    exec_local_cmd(From, To, Request#adhoc_command{node = ?NS_ADMINX(Node), action = Action}, Allow);

cmd(Acc, #adhoc_command{} = Request, _From, _To )->
    cmd(Acc, Request).

cmd(_Acc, #adhoc_command{node = <<"users">>, xdata = _Params, action = Action} = Request)
    when Action =:= execute orelse Action =:= complete ->
    Host = eims:host(),
    case get_users(Host) of
        [_ |_] = Res->
            xmpp_util:make_adhoc_response(
                Request,
                #adhoc_command{
                    xdata = #xdata{
                        type = form,
                        fields = [?HFIELD(),
                            #xdata_field{
                                type = 'text-multi',
                                label = <<"The list of all users">>,
                                var = <<"reguserjids">>,
                                values = Res
                            }]},
                    status = completed,
                    node = Request#adhoc_command.node,
                    sid = Request#adhoc_command.sid
                }
             );
        Err ->
            Err
    end;


cmd(_Acc, #adhoc_command{node = ?NS_NODE_BAN, xdata = undefined, action = execute} = Request) ->
    Form = generate_ban_form(),
    xmpp_util:make_adhoc_response(
        Request,
        #adhoc_command{
            status = executing,
            node = Request#adhoc_command.node,
            sid = Request#adhoc_command.sid,
            xdata = Form,
            actions = #adhoc_actions{complete = true}
        }
    );
cmd(_Acc, #adhoc_command{node = ?NS_NODE_BAN, xdata = Form, action = Action} = Request)
    when Action =:= execute orelse Action =:= complete ->
    case handle_ban_form(Form) of
        {ok, ParsedJID} ->
            insert_banned(ParsedJID),
            xmpp_util:make_adhoc_response(
                Request,
                #adhoc_command{
                    status = completed,
                    node = Request#adhoc_command.node,
                    sid = Request#adhoc_command.sid
                }
            );
        Err ->
            Err
    end;
cmd(_Acc, #adhoc_command{action = cancel} = Request) ->
    xmpp_util:make_adhoc_response(
        Request,
        #adhoc_command{
            status = canceled,
            node = Request#adhoc_command.node,
            sid = Request#adhoc_command.sid
        }
    );
cmd(Acc, _Request) -> Acc.


%% Ban
all_banned() ->
    lists:flatten([mnesia:dirty_index_read(eims_storage, Deny, access) || Deny <- [deny, global_deny]]).
list_banned() ->
    [{User, (MS * 1000000 + S) * 1000000 + US}
        || #eims_storage{jid = {User, _Server}, tstamp = {MS, S, US}} <- all_banned()].
%%banned_jids() ->
%%    [<<User/binary, "@", Server/binary>> || #eims_storage{jid = {User, Server}} <- all_banned()].
banned_jids() ->
    [case Id of MainId -> <<Nick/binary,"`s main account">>;
                     _ -> <<User/binary, "@", Server/binary>> end ||
        #eims_storage{jid = {User, Server}, id = Id, main_account_id = MainId, nick = Nick } <- all_banned()].
banned_jids(MainId) ->
    [<<User/binary, "@", Server/binary>> || #eims_storage{jid = {User, Server}}
        <- mnesia:dirty_index_read(eims_storage, MainId, main_account_id)].

set_access(#jid{luser = User, lserver = Server}, Deny) when Deny == deny ->
    case mnesia:dirty_read(eims_storage, {User, Server}) of
        [USerStorage] -> mnesia:dirty_write(USerStorage#eims_storage{access = Deny, tstamp = os:timestamp()});
        [] -> {error, user_not_found}
    end;
set_access(JID, Deny) when is_binary(JID) ->
    set_access(string_to_jid(JID), Deny).

insert_banned(JID) ->
    set_access(JID, deny).

remove_banned(#jid{luser = User, lserver = Server}) ->
    case mnesia:dirty_read(eims_storage, {User, Server}) of
        [#eims_storage{}=USerStorage] -> mnesia:dirty_write(USerStorage#eims_storage{access = allow, tstamp = 0});
%        [#eims_storage{access = A} = USerStorage] when A =/= global_deny -> mnesia:dirty_write(USerStorage#eims_storage{access = allow, tstamp = 0});
        [] -> {error, user_not_found}
    end;
remove_banned(JID) when is_binary(JID) ->
    remove_banned(string_to_jid(JID)).

%% When main account is banned that is global ban
%%is_global_banned(MainId) ->
%%    Banned = mnesia:dirty_read(eims_storage, MainId, main_account_id),
%%    case lists:keyfind(deny, #eims_storage.access, Banned) of
%%        #eims_storage{} -> true;
%%        false -> false
%%    end.

is_global_banned(#jid{luser = User, lserver = Server}) ->
    case mnesia:dirty_read(eims_storage, {User, Server}) of
        [#eims_storage{access = deny}] -> true;
        _ -> false
    end.

is_banned(#jid{luser = User, lserver = Server}) ->
    case mnesia:dirty_read(eims_storage, {User, Server}) of
        [#eims_storage{access = Deny}] when Deny == deny -> true;
        _ -> false
    end;
is_banned(Id) when is_integer(Id)->
    case mnesia:dirty_index_read(eims_storage, Id, id) of
        [#eims_storage{access = Deny}] when Deny == deny -> true;
        _ -> false
    end;
is_banned(JID) when is_binary(JID) ->
    is_banned(string_to_jid(JID)).

get_title(?NS_NODE_BAN) -> <<"Ban Account...">>.

get_items(#jid{luser = U, lserver = S}, Server) ->
    case acl:match_rule(Server, eims_admin, #{usr => {U, S, <<>>}}) of
        allow ->
            lists:map(fun(Item) when is_binary(Item) ->
                #disco_item{jid = jid:make(Server), node = Item, name = get_title(Item)}
                      end, ?ITEMS);
        _ -> []
    end.



-spec unban_command(jid(), jid()) ->   ok | {error, stanza_error()}.
unban_command(#jid{luser = U, lserver = S} = _From, #jid{lserver = Server} = To) ->
    case acl:match_rule(Server, eims_admin, #{usr => {U, S, <<>>}}) of
        allow -> remove_banned(To);
        deny -> xmpp:err_forbidden(<<"Command disallowed for you">>, ?DEFAULT_LANG)
    end.


generate_ban_form() ->
    #xdata{
        type = form,
        title = <<"Ban Account for Chat">>,
        fields = [
            #xdata_field{
                type = hidden,
                var = <<"FORM_TYPE">>,
                values = [?NS_NODE_BAN]
            },
            #xdata_field{
                type = 'jid-single',
                var = <<"jid">>,
                label = <<"JID to BAN">>
            }
        ]
    }.

handle_ban_form(XData) ->
    case xmpp_util:get_xdata_values(<<"jid">>, XData) of
        [JID] ->
            try jid:decode(JID) of
                #jid{luser = LUser} = ParsedJID when LUser =/= <<>> ->
                    {ok, ParsedJID};
                _ ->
                    {error, xmpp:err_not_acceptable(<<"Use a valid JID">>, ?DEFAULT_LANG)}
            catch
                error:{bad_jid, _} ->
                    {error, xmpp:err_not_acceptable(<<"Use a valid JID">>, ?DEFAULT_LANG)}
            end;
        _ ->
            {error, xmpp:err_not_acceptable(<<"Use a valid JID">>, ?DEFAULT_LANG)}
    end.

%% Getting of info about users

-spec get_users(binary()) ->  [map()].
get_user(U,S) ->
    Acl = acl:match_rule(S, eims_admin, #{usr => {U, S, <<>>}}),
    {Nick, Roles} = case eims:get_storage_by_field({U, S}) of
                        #eims_storage{roles = Rs, nick = N} when Acl == allow -> {N, [<<"admin">>]};
                        #eims_storage{roles = Rs, nick = N} ->
                            case Rs of [] ->{N, [<<"none">>]}; _ -> {N, Rs} end;
                        _  when Acl == allow -> {U, [<<"admin">>]};
                        _ ->
                            {_PrivateData, UStorage} = eims:gen_summary(U, U),
                            ok = mnesia:dirty_write(UStorage), {U, [<<"none">>]} end,
    #{<<"User">> => <<U/binary,"@", S/binary>>,
        <<"Nick">> => Nick,
        <<"Last Activity">> => get_last(U),
        <<"Roles">> => Roles
    }.
get_users(Host) ->
    [ jiffy:encode(get_user(U,S))|| {U,S} <- ejabberd_auth:get_users(Host) ].
%%    ct:print("USERS!!!!! ~p", [Res]),


get_last(User) ->
    case mod_admin_extra:get_last(User, eims:host()) of
        {T, "ONLINE"} -> <<"ONLINE">>;
        {T, "NOT FOUND"} -> <<"Never logged in">>;
        {Time, _} -> Time
    end.
%%get_last_info(User, Server) ->
%%    case gen_mod:is_loaded(Server, mod_last) of
%%        true ->
%%            mod_last:get_last_info(User, Server);
%%        false ->
%%            not_found
%%    end.

get_form(_Host, ?NS_ADMINL(<<"add-user">>), Lang) ->
    {result,
        #xdata{title = tr(Lang, ?T("Add User")),
            type = form,
            fields = [?HFIELD(),
                #xdata_field{type = 'jid-single',
                    label = tr(Lang, ?T("Jabber ID")),
                    required = true,
                    var = <<"accountjid">>},
                #xdata_field{type = 'text-private',
                    label = tr(Lang, ?T("Password")),
                    required = true,
                    var = <<"password">>},
                #xdata_field{type = 'text-private',
                    label = tr(Lang, ?T("Password Verification")),
                    required = true,
                    var = <<"password-verify">>}]}};
get_form(_Host, ?NS_ADMINL(<<"delete-user">>), Lang) ->
    {result,
        #xdata{title = tr(Lang, ?T("Delete User")),
            type = form,
            fields = [?HFIELD(),
                #xdata_field{type = 'jid-multi',
                    label = tr(Lang, ?T("Jabber ID")),
                    required = true,
                    var = <<"accountjids">>}]}}.

-spec tr(binary(), binary()) -> binary().
tr(Lang, Text) ->
    translate:translate(Lang, Text).

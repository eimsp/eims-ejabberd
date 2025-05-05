%%%-------------------------------------------------------------------
%%% @doc
%%% external authorization for EIMS
%%% @end
%%%-------------------------------------------------------------------
-module(ejabberd_auth_eims).

-behaviour(ejabberd_auth).
-compile(export_all).
-export([start/1, stop/1, reload/1, set_password/3,
    check_password/4,
    try_register/3, user_exists/2, remove_user/2,
    store_type/1, plain_password_required/1, get_oauth2_host_token/2]).


-include_lib("logger.hrl").
-include_lib("xmpp/include/xmpp.hrl").
-include("eims.hrl").


-define(HTTP_TIMEOUT, 10000).
-define(CONNECT_TIMEOUT, 8000).

%%%----------------------------------------------------------------------
%%% API
%%%----------------------------------------------------------------------
start(_Host) ->
    case is_map(eims:connection_opts()) of
        true ->
            ok;
        _ ->
            ?ERROR_MSG("Integrated service api host [auth_opts > path_prefix] is not configured", []),
            {error, bad_config}
    end.

stop(_Host) ->
    ok.

reload(_Host) ->
    ok.

plain_password_required(_) -> true.

store_type(_) -> external.

check_password(User, AuthzId, _Server, _Password) when AuthzId =/= <<>> andalso AuthzId =/= User ->
    {nocache, false};
%% Add here check password for external host service
check_password(User, AuthzId, Server, <<"hserv-web-app;", Password/binary>>) ->
    case mod_adhoc_eims:is_banned(jid:make(User, Server)) of
        true -> {nocache, false};
        false -> check_password_extauth(User, AuthzId, Server, Password)
    end;
%%
check_password(_User, _AuthzId, _Server, _Password) ->
    %% ?ERROR_MSG("check_password failed, User ~p, AuthzId: ~p, Server: ~p, Pwd: ~p", [User, AuthzId, Server, Password]),
    {nocache, false}.

set_password(_User, _Server, _Password) ->
    {error, not_allowed}.

try_register(_User, _Server, _Password) ->
    {error, not_allowed}.

user_exists(_User, _Server) ->
    {nocache, false}.

remove_user(_User, _Server) ->
    {error, not_allowed}.

check_password_extauth(_User, _AuthzId, _Server, <<>>) ->
    {nocache, false};
check_password_extauth(User, _AuthzId, Server, Password) ->
    case do_check_password(get_oauth2_host_token(Password, Server), User, Server) of
        Res when is_boolean(Res) -> {nocache, Res};
        {error, Reason} ->
            {Tag, _} = failure(User, Server, check_password, Reason),
            {Tag, false}
    end.

do_check_password(undefined, _User, _Server) ->
    false;

do_check_password(_OAuth2, undefined, _Server) ->
    false;

%% Add here logic of check password for external host service
do_check_password([_Host, Token, RefreshToken], User, Server) ->
    JID = jid:make(User, Server),
    case eims_rest:get_account_summary_req(JID, Token) of
        {ok, 200,
            #{<<"system_name">> := AccountSystemName,
                <<"jid_node">> := AccountJid,
                <<"nick">> := Nickname,
                <<"id">> := Id} = AccountSummary
             } ->
            [VirtualHost|_] = ejabberd_option:hosts(),
            Email = maps:get(<<"email">>, AccountSummary, undefined),
            MainEmail = maps:get(<<"main_email">>, AccountSummary, Email),
            MainSystemName = maps:get(<<"main_system_name">>, AccountSummary, AccountSystemName),
            Roles = maps:get(<<"roles">>, AccountSummary, undefined),
            MainId = case catch maps:get(<<"main_account_id">>, AccountSummary) of
                         {'EXIT', _} -> Id; %% TODO in future remove this construction
                         Value -> Value
                     end,
            IsBanned = mod_adhoc_eims:is_banned(MainId),
            Nick = case Nickname of
                       <<"whale.", _/binary>> ->
                           Nickname;
                       _ ->
                           <<"whale.", Nickname/binary>>
                   end,
            case {Nickname, AccountJid} of
                {<<_/integer, _/binary>>, User} when not IsBanned ->
                    %% CurrentEquity = maps:get(<<"equity">>, AccountSummary, undefined),
                    %%noinspection Erlang17Syntax
                    PrivateData = #{
                        %% private data is becomes sorted in storage, space is always first
                        %% prepend "whale." to nicks from EIMS, nick here:
                        <<" ">> => Nick,
                        <<"nick">> => Nick, %% nick on EIMS
                        <<"email">> => Email
%%                        <<"system_name">> => AccountSystemName,
%%                        <<"id">> => Id,
%%                        <<"main_account_id">> => MainId,
%%                        <<"main_system_name">> => MainSystemName,
%%                        <<"main_email">> => MainEmail,
%%                        <<"roles">> => Roles
                    },
                    case banword_gen_server:member({en, binary_to_list(Nickname)}) of
                        false ->
                            ok = mnesia:dirty_write(#eims_storage{
                                jid = {AccountJid, VirtualHost},
                                nick = Nick,
                                id = Id,
                                email = Email,
                                system_name = AccountSystemName,
                                main_account_id = MainId,
                                main_system_name= MainSystemName,
                                main_email= MainEmail,
                                roles = Roles}),
                            store_private(PrivateData, Jid = jid:make(AccountJid, Server)),
                            eims_rest:send_delay_refresh({Jid, {Token, RefreshToken}}),
                            %% mod_admin_extra:set_nickname(User, Server, Nickname),
                            %% Rooms = mod_muc:get_online_rooms(<<"conference.", Server/binary>>),
                            %% mod_muc_admin:muc_register_nick(Nickname, jid:encode(Jid), <<"conference.", Server/binary>>),
                            true;
                        _ ->
                            ?dbg("user nick ~s is badword", [Nickname]),
                            false
                    end;
                _ when IsBanned ->
                    ?dbg("user ~s@~s is banned", [User, Server]),
                    Storage = #eims_storage{
                        jid = {AccountJid, VirtualHost},
                        nick = Nick,
                        id = Id,
                        email = Email,
                        system_name = AccountSystemName,
                        main_account_id = MainId,
                        main_system_name= MainSystemName,
                        main_email= MainEmail,
                        roles= Roles},
                    BinMainId = integer_to_binary(MainId),
                    case mnesia:dirty_index_read(eims_storage, Id, id) of
                        [#eims_storage{jid ={BinMainId, VirtualHost}, access = deny, tstamp = Tstamp}]->
                            mnesia:dirty_delete(eims_storage,{BinMainId, VirtualHost}),
                            mnesia:dirty_write(Storage#eims_storage{access = deny, tstamp = Tstamp});
                        [#eims_storage{ id= MainId, main_account_id = MainId, tstamp = Tstamp }]->
                            mnesia:dirty_write(Storage#eims_storage{access = deny, tstamp = Tstamp });
                        _ -> mnesia:dirty_write(Storage) %% because only non banned subaccount comes here when main account is banned
                    end,
                    false;
                _Err ->
                    ?dbg("invalid nickname ~p for jid ~p", [Nickname, AccountJid]),
                    false
            end;
        Err ->
            ?dbg("invalid get_account_summary_req for ~p: ~p", [User, Err]),
            false
    end.
%%
store_private(Data, Jid) ->
    Children = lists:map(fun({Key, Value}) ->
        #xmlel{name = Key, children = [{xmlcdata, Value}]}
    end, maps:to_list(Data)),
    Xml = #xmlel{name = <<"eims">>, children = Children},
    mod_private:set_data(Jid, [{?NS_EIMS, Xml}]).

-spec failure(binary(), binary(), atom(), any()) -> {nocache, {error, db_failure}}.
failure(User, Server, Fun, Reason) ->
    ?ERROR_MSG("External authentication program failed when calling "
    "'~ts' for ~ts@~ts: ~p", [Fun, User, Server, Reason]),
    {nocache, {error, db_failure}}.


%% Add here logic of get token for external host service
get_oauth2_host_token(Password, Server) ->
    HostApiHostMap =
        case eims:connection_opts() of
            undefined -> #{};
            M -> M
        end,
    ApiHost =
        case binary_to_list(maps:get(Server, HostApiHostMap, eims:hservice_host())) of
            "http" ++_ = H1 -> H1;
            H2 -> "https://" ++ H2
        end,
    case binary:split(Password, <<";">>, [global]) of
        [_, Token, RefreshToken] ->
            [ApiHost, Token, RefreshToken];
        [Token, RefreshToken] ->
            [ApiHost, Token, RefreshToken];
        _ ->
            undefined
    end.

%%


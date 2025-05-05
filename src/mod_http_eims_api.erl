%%%-------------------------------------------------------------------
%%% @doc
%%%Some EIMS specific REST commands
%%% @end
%%%-------------------------------------------------------------------
-module(mod_http_eims_api).
-compile(export_all).
-behaviour(gen_mod).

-export([start/2, stop/1, reload/3, process/2, depends/2,
    mod_options/1, mod_doc/0]).

-include_lib("xmpp/include/xmpp.hrl").
-include("logger.hrl").
-include("ejabberd_http.hrl").
-include("ejabberd_stacktrace.hrl").
-include("translate.hrl").
-include("eims.hrl").

-define(DEFAULT_API_VERSION, 0).

-define(CT_PLAIN,
    {<<"Content-Type">>, <<"text/plain">>}).

-define(CT_XML,
    {<<"Content-Type">>, <<"text/xml; charset=utf-8">>}).

-define(CT_JSON,
    {<<"Content-Type">>, <<"application/json">>}).

-define(CT_JSONP,
    {<<"Content-Type">>, <<"application/javascript">>}).

-define(AC_ALLOW_ORIGIN,
    {<<"Access-Control-Allow-Origin">>, <<"*">>}).

-define(AC_ALLOW_METHODS,
    {<<"Access-Control-Allow-Methods">>,
        <<"GET">>}).

-define(AC_ALLOW_HEADERS,
    {<<"Access-Control-Allow-Headers">>,
        <<"Content-Type, Authorization, X-Admin">>}).

-define(AC_MAX_AGE,
    {<<"Access-Control-Max-Age">>, <<"86400">>}).

-define(OPTIONS_HEADER,
    [?CT_PLAIN, ?AC_ALLOW_ORIGIN, ?AC_ALLOW_METHODS,
        ?AC_ALLOW_HEADERS, ?AC_MAX_AGE]).

-define(HEADER(CType),
    [CType, ?AC_ALLOW_ORIGIN, ?AC_ALLOW_HEADERS]).

%% -------------------
%% Module control
%% -------------------

start(_Host, _Opts) ->
    ok.

stop(_Host) ->
    ok.

mod_options(_Host) ->
    [
        {redirect_uri, "/eims/server_auth"}
    ].

mod_opt_type(redirect_uri) ->
    econf:string().

reload(_Host, _NewOpts, _OldOpts) ->
    ok.

depends(_Host, _Opts) ->
    [].

%% ------------------
%% request processing
%% ------------------
get_banword_file(Lang) when is_atom(Lang) ->
    FileName = proplists:get_value(Lang, gen_mod:get_module_opt(global, mod_pottymouth, blacklists)),
    case filelib:is_file(FileName) of
        true -> FileName;
        _ -> {error, file_not_found}
    end;
get_banword_file(Lang) when is_binary(Lang) ->
    get_banword_file(binary_to_atom(Lang)).
%%process(Call, Request) ->
%%    ?DEBUG("~p~n~p", [Call, Request]), ok;
process([<<"react.html">>], #request{method = 'GET'} = _Req) ->
    {404, ?OPTIONS_HEADER, []};
process([<<"blacklist">>], #request{method = 'POST', q = Data} = _Req) ->
    #{<<"remove">> := Removed, <<"checksum">> := _Checksum, <<"args">> := #{<<"lang">> := Lang} = Args} =
        jiffy:decode(proplists:get_value(<<"acc">>, Data), [return_maps]),
    case mod_http_eims_api:check_blacklist_access(Args) of
        true ->
            case get_banword_file(Lang) of
                {error, file_not_found} ->
                    {400, ?HEADER(?CT_PLAIN), <<"Blacklist for ", Lang/binary, " language not found">>};
                PathName ->
                    BlackList = readlines(PathName),
%%                  Checksum = integer_to_binary(erlang:phash2(BlackList)), %% TODO check checksum?
                    NewBlackList = [<<BadWord/binary, "\n">> || BadWord <- BlackList, not lists:member(BadWord, Removed)],
                    ok = file:write_file(PathName, iolist_to_binary(string:strip(binary_to_list(iolist_to_binary(NewBlackList)), right, $\n))),
                    ok = banword_gen_server:reload(case binary_to_atom(Lang) of default -> en; L -> L end),
                    {200, ?HEADER(?CT_PLAIN), <<"Blacklist was successfully updated">>}
            end;
        _ ->
            badrequest_response(<<"not allowed">>)
    end;
process(_, #request{method = 'POST'}) ->
    badrequest_response(<<"not_allowed">>);
process([Call], #request{method = 'GET', q = Data, ip = {IP, _}} = Req) ->
    Version = get_api_version(Req),
    try
        Args = case Data of
                   [{nokey, <<>>}] -> [];
                   _ -> Data
               end,
        %% log(Call, Args, IP),
        perform_call(Call, Args, Req, Version)
    catch
        %% TODO We need to refactor to remove redundant error return formatting
        throw:{error, unknown_command} ->
            json_format({404, 44, <<"Command not found.">>});
        ?EX_RULE(_, _Error, Stack) ->
            log(Call, Data, IP),
            StackTrace = ?EX_STACK(Stack),
            ?DEBUG("Bad Request: ~p ~p", [_Error, StackTrace]),
            badrequest_response()
    end;
process([_Call], #request{method = 'OPTIONS', data = <<>>}) ->
    {200, ?OPTIONS_HEADER, []};
process(_, #request{method = 'OPTIONS'}) ->
    {400, ?OPTIONS_HEADER, []};
process(_Path, _Request) ->
    json_error(400, 40, <<"unsupported">>).

perform_call(Command, Args, Req, Version) ->
    case
        catch(binary_to_existing_atom(Command, utf8)) of
        Call when is_atom(Call) ->
            Result = handle(Call, Args, Req, Version),
            json_format(Result);
        _ ->
            json_error(404, 40, <<"not_found">>)
    end.

% get API version N from last "vN" element in URL path
get_api_version(#request{path = Path}) ->
    get_api_version(lists:reverse(Path));
get_api_version([<<"v", String/binary>> | Tail]) ->
    case catch binary_to_integer(String) of
        N when is_integer(N) ->
            N;
        _ ->
            get_api_version(Tail)
    end;
get_api_version([_Head | Tail]) ->
    get_api_version(Tail);
get_api_version([]) ->
    ?DEFAULT_API_VERSION.

%% ----------------
%% command handlers
%% ----------------

%% TODO Check accept types of request before decided format of reply.

% generic ejabberd command handler
handle(Call, Args, Req, Version) when is_atom(Call), is_list(Args) ->
    Args2 = [{misc:binary_to_atom(Key), Value} || {Key, Value} <- Args],
    try handle2(Call, Args2, Req, Version)
    catch throw:not_found ->
        {404, <<"not_found">>};
        throw:{not_found, Why} when is_atom(Why) ->
            {404, misc:atom_to_binary(Why)};
        throw:{not_found, Msg} ->
            {404, iolist_to_binary(Msg)};
        throw:not_allowed ->
            {401, <<"not_allowed">>};
        throw:{not_allowed, Why} when is_atom(Why) ->
            {401, misc:atom_to_binary(Why)};
        throw:{not_allowed, Msg} ->
            {401, iolist_to_binary(Msg)};
        throw:{error, account_unprivileged} ->
            {403, 31, <<"Command need to be run with admin privilege.">>};
        throw:{error, access_rules_unauthorized} ->
            {403, 32, <<"AccessRules: Account does not have the right to perform the operation.">>};
        throw:{invalid_parameter, Msg} ->
            {400, iolist_to_binary(Msg)};
        throw:{error, Why} when is_atom(Why) ->
            {400, misc:atom_to_binary(Why)};
        throw:{error, Msg} ->
            {400, iolist_to_binary(Msg)};
        throw:Error when is_atom(Error) ->
            {400, misc:atom_to_binary(Error)};
        throw:Msg when is_list(Msg); is_binary(Msg) ->
            {400, iolist_to_binary(Msg)};
        ?EX_RULE(Class,  {unregistered_route, Host} = Error, Stack) ->
            StackTrace = ?EX_STACK(Stack),
            ?ERROR_MSG("REST API Error: "
            "~ts(~p) -> ~p:~p ~p",
                [Call, hide_sensitive_args(Args),
                    Class, Error, StackTrace]),
            {500, <<"invalid_host ", Host/binary>>};
        ?EX_RULE(Class, Error, Stack) ->
            StackTrace = ?EX_STACK(Stack),
            ?dbg("REST API Error: "
            "~ts(~p) -> ~p:~p ~p",
                [Call, hide_sensitive_args(Args),
                    Class, Error, StackTrace]),
            ?ERROR_MSG("REST API Error: "
            "~ts(~p) -> ~p:~p ~p",
                [Call, hide_sensitive_args(Args),
                    Class, Error, StackTrace]),
            {500, <<"internal_error">>}
    end.

handle2(Call, Args, Req, Version) when is_atom(Call), is_list(Args) ->
    case execute_command(Call, Args, Req, Version) of
        {error, Error} ->
            throw(Error);
        Res ->
            format_result(Call, Args, Res, Version)
    end.


%% ----------------
%% internal helpers
%% ----------------

readlines(FileName) ->
    case file:open(FileName, [read]) of
        {ok, Device} ->
            try get_all_lines(Device)
            after file:close(Device)
            end;
        {error, Reason} = _Err ->
            ?DEBUG("ERROR: can not open file ~p, reason: ~p", [FileName, Reason]),
            []
    end.

get_all_lines(Device) ->
    case file:read_line(Device) of
        eof  -> [];
        {ok, Line} -> [list_to_binary(string:strip(Line, right, $\n))] ++ get_all_lines(Device)
    end.

check_blacklist_access(Args) when is_map(Args) ->
    check_blacklist_access(maps:to_list(Args));
check_blacklist_access([{K, _} | _] = Args) when is_binary(K) ->
    check_blacklist_access([{binary_to_atom(Key), V}|| {Key, V} <- Args]);
check_blacklist_access([{K, _} | _] = Args) when is_atom(K) -> %% TODO check for expired time
    Args2 = [proplists:get_value(Key, Args, <<>>) || Key <- [user, lang, t]],
    Hash = proplists:get_value(hash, Args, <<>>),
    eims:check_hash(Hash, Args2);
check_blacklist_access(_) ->
    false.

execute_command(blacklist, Args, _Req, _Version) ->
    case check_blacklist_access(Args) of
        true ->
            Lang = proplists:get_value(lang, Args),
            case get_banword_file(Lang) of
                {error, file_not_found} ->
                    badrequest_response(<<"Blacklist for ", Lang/binary, " language not found">>);
                PathName ->
                    Data = readlines(PathName),
                    CheckSum = erlang:phash2(Data),
                    {200, #{<<"checksum">> => integer_to_binary(CheckSum), <<"lang">> => Lang, <<"blacklist">> => Data}}
            end;
        _ -> {400, #{<<"error">> => <<"access denied">>}}
    end;
execute_command(server_auth, Args, _Req, _Version) ->
    eims:check_sync_hserv(eims_rest:auth_command(maps:from_list(Args)));
execute_command(muc_list, Args, _Req, _Version) ->
    Host = case proplists:get_value(host, Args, undefined) of
               <<"conference.", _/binary>> = H ->
                   H;
               _ ->
                   throw(bad_conference_host)
           end,
    Rooms =
        memoize({?MODULE, muc_list, Host},
            fun () ->
                lists:filtermap(fun public_room/1, mod_muc_admin:muc_online_rooms(Host))
            end, 2000),
    {200, Rooms};
execute_command(_Call, _Args, _Req, _Version) ->
    throw(not_found).

public_room(RoomName) ->
    case re:split(RoomName,<<"@">>) of
        [Name, Host] ->
            Opts = mod_muc_admin:get_room_options(Name,Host),
            case proplists:get_value(<<"public">>, Opts, undefined) of
                <<"true">> ->
                    {true, maps:from_list([{<<"jid">>, RoomName} | lists:filter(
                        fun
                            ({<<"title">>,_}) ->
                                true;
                            ({<<"description">>,_}) ->
                                true;
                            ({<<"lang">>,_}) ->
                                true;
                            (_) ->
                                false
                        end, Opts)])};
                _ ->
                    false
            end;
        _ ->
            false
    end.

format_result(_Call, Args, Res, _Version) ->
    case proplists:get_value(callback, Args, undefined) of
        undefined ->
            Res;
        Callback ->
            {jsonp, Callback, Res}
    end.

badrequest_response() ->
    badrequest_response(<<"400 Bad Request">>).
badrequest_response(Body) ->
    json_response(400, jiffy:encode(Body)).

json_format({jsonp, Callback, {Code, Result}}) ->
    {Code, ?HEADER(?CT_JSONP), <<Callback/binary, "(", (jiffy:encode(Result))/binary, ")">>};
json_format({301, RedirectUri}) ->
    {301, [{<<"Location">>, RedirectUri}], <<>>};
json_format({Code, Result}) ->
    json_response(Code, jiffy:encode(Result));
json_format({HTMLCode, JSONErrorCode, Message}) ->
    json_error(HTMLCode, JSONErrorCode, Message).

json_response(Code, Body) when is_integer(Code) ->
    {Code, ?HEADER(?CT_JSON), Body}.

%% HTTPCode, JSONCode = integers
%% message is binary
json_error(HTTPCode, JSONCode, Message) ->
    {HTTPCode, ?HEADER(?CT_JSON),
        jiffy:encode({[{<<"status">>, <<"error">>},
            {<<"code">>, JSONCode},
            {<<"message">>, Message}]})
    }.

log(Call, Args, {Addr, Port}) ->
    AddrS = misc:ip_to_list({Addr, Port}),
    ?INFO_MSG("API call ~ts ~p from ~ts:~p", [Call, hide_sensitive_args(Args), AddrS, Port]);
log(Call, Args, IP) ->
    ?INFO_MSG("API call ~ts ~p (~p)", [Call, hide_sensitive_args(Args), IP]).

hide_sensitive_args(Args=[_H|_T]) ->
    lists:map( fun({<<"password">>, Password}) -> {<<"password">>, ejabberd_config:may_hide_data(Password)};
        ({<<"newpass">>,NewPassword}) -> {<<"newpass">>, ejabberd_config:may_hide_data(NewPassword)};
        (E) -> E end,
        Args);
hide_sensitive_args(NonListArgs) ->
    NonListArgs.

mod_doc() ->
    #{desc =>
    [?T("This module provides a ReST API for public EIMS commands "
    "using JSON data."), "",
        ?T("To use this module, in addition to adding it to the 'modules' "
        "section, you must also add it to 'request_handlers' of some "
        "listener."), "",
        ?T("To use a specific API version N, when defining the URL path "
        "in the request_handlers, add a 'vN'. "
        "For example: '/api/v2: mod_http_eims_api'")]}.

memoize(Key, Fun, TimeoutMs) ->
    CurrentTs = eims:sys_time(),
    ValidTs =  CurrentTs - TimeoutMs,
    case ets:info(?MODULE, named_table) of
        undefined ->
            ets:new(?MODULE, [public, named_table]);
        _ ->
            ok
    end,
    case ets:lookup(?MODULE, Key) of
        [{_, {Ts, Cached}}] when ValidTs < Ts ->
            Cached;
        _ ->
            ets:insert(?MODULE, {Key, {CurrentTs, R = Fun()}}), R
    end.

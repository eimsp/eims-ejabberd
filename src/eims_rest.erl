%%%-------------------------------------------------------------------
%%% @doc
%%% @doc
%%% EIMS REST API
%%% @end
%%%-------------------------------------------------------------------
-module(eims_rest).
-compile(export_all).
%% API
-export([]).

-include_lib("xmpp/include/xmpp.hrl").
-include("ejabberd_http.hrl").
-include("logger.hrl").
-include("eims.hrl").

-define(URI_AUTH, "/api/v2/public/auth").
-define(URI_POSITION, "/api/v2/private/get_position").
-define(URI_SUMMARY, "/api/v2/private/get_account_summary").
-define(URI_ACCOUNT_SUMMARY, "/api/v2/private/chat_get_account_summary").
-define(URI_TRADE_VOLUMES, "/api/v2/public/get_trade_volumes").
-define(URI_STATS, "/api/v2/private/get_stats").

%% -define(REDIRECT_URI, "server_auth").
-define(REDIRECT_CLIENT, <<"/react.html?">>).

-define(HTTP_TIMEOUT, 5000).
-define(CONNECT_TIMEOUT, 5000).
-define(HTTP_OPTS, [{connect_timeout, ?CONNECT_TIMEOUT}, {timeout, ?HTTP_TIMEOUT}]).

-define(EXP_INTERVAL, 30000). %% milliseconds

auth_req_format(RedirectUri, Code) ->
	Data =
		#{<<"method">> => <<"public/auth">>,
		  <<"params">> =>
			#{<<"grant_type">>    => <<"authorization_code">>,
			  <<"redirect_uri">>  => iolist_to_binary(RedirectUri),
			  <<"code">>          => iolist_to_binary(Code)}},
	binary_to_list(jiffy:encode(Data)).

ports() -> [P || {{P, _, tcp}, ejabberd_http, _} <- ejabberd_option:listen()].

port(N) -> lists:nth(N, ports()).
port()  -> port(1).

host(UriMap) ->
	host(UriMap, 1).
host(#{} = UriMap, N) ->
	Host = eims:host(),
	UriMap2 = UriMap#{host => Host},
	case Host of
		<<"localhost">> ->
			UriMap2#{scheme => "http", port => port(N)};
		_ ->
			UriMap2#{scheme => "https"}
	end.
host() ->
	uri_string:normalize(host(#{path => <<"react.html">>})). %% This function didn't work for example I use it for second redirect
redirect_uri() ->
%%	{ok, Config} = file:consult("ejabberd.yml"),
	Modules = ejabberd_config:get_option(modules),
	RedirectUri = proplists:get_value(redirect_uri, proplists:get_value(mod_http_eims_api, Modules)),
	uri_string:normalize(host(#{path => RedirectUri}, 2)).

auth_uri(State, Scope) ->
	Host = eims:host(),
	#{Host := ISost, <<"client_id">> := ClientId} = eims:connection_opts(),
	Query = uri_string:compose_query(
		[{"client_id", ClientId},
			{"scope", Scope},
			{"state", State},
			{"response_type", "code"},
			{"redirect_uri", redirect_uri()}]),
	uri_string:normalize(#{scheme => "https", host => ISost, path => "app_authorization", query => Query}).

blacklist_uri(Query) ->
	Host = eims_rest:host(#{query => Query, port => port()}),
	uri_string:recompose(Host#{path => "static/blacklist.html"}).

auth_header(Uri, RequestBody, #{<<"client_id">> := ClientId, <<"client_secret">> := ClientSecret}) ->
	Timestamp = integer_to_list(eims:sys_time()),
	Nonce = eims:gen_nonce(),
	RequestData = "POST" ++ "\n" ++ Uri ++ "\n" ++ RequestBody ++ "\n",
	StringToSign = Timestamp ++ "\n" ++ Nonce ++ "\n" ++ RequestData,
	Sig = crypto:mac(hmac, sha256, ClientSecret, StringToSign),
	Signature = [element(C + 1, {$0, $1, $2, $3, $4, $5, $6, $7, $8, $9, $a, $b, $c, $d, $e, $f}) || <<C:4>> <= Sig],
	Auth = lists:flatten(io_lib:format("app-deri-hmac-sha256 id=~s,ts=~s,nonce=~s,sig=~s",
		[ClientId, Timestamp, Nonce, Signature])),
	{"Authorization", Auth}.

auth_command(#{state := <<"react">>} = Map) ->
	Host = eims:host(),
	Query = uri_string:compose_query([{atom_to_binary(K), V} || {K, V} <- maps:to_list(Map)]),
	fun() -> {301, <<"https://", Host/binary, ?REDIRECT_CLIENT/binary, Query/binary>>} end;
auth_command(#{state := State, code := Code}) ->
	StateMap = #{jid := Jid, nonce := AuthNonce} = binary_to_term(base64:decode(uri_string:unquote(State))),
	JID = #jid{luser = User, lserver = Host} = jid:decode(Jid),
	SysTime = eims:sys_time(),
	case eims:get_tokens(JID) of
		AuthNonce when SysTime - AuthNonce < ?EXP_INTERVAL ->
			ConnOpts = eims:connection_opts(),
			#{Host := ISHost} = ConnOpts,
			RedirectUri = ?MODULE:redirect_uri(),
			RequestBody = auth_req_format(RedirectUri, Code),
			Header = auth_header(Uri = ?URI_AUTH, RequestBody, ConnOpts),
			Request = {"https://" ++ binary_to_list(ISHost) ++ Uri, [Header], [], RequestBody},
			fun() ->
				case httpc:request(post, Request, ?HTTP_OPTS, []) of
					{ok, {{_, 200, _}, _, Body}} ->
						send_delay_refresh({JID, #eims_auth{access_token = Token} = get_priv_data(Body)}),
						auth_post(StateMap),
						case User of
							<<"whale.", _/binary>> -> {200, ok};
							_ ->
%%								Is_EjUser = eims:is_ejuser(User), %% Is_EjUser = true always
								case get_account_summary_req(JID, Token) of %% TODO discuss in future. Temporary solve
									{ok, 200, #{<<"email">> := Email} = _AccountSummary} ->
										case eims:get_storage_by_field({User, Host}) of
											#eims_storage{} = UStor ->
												mnesia:dirty_write(UStor#eims_storage{jid = {User, Host}, email = Email});
%%											_ when not Is_EjUser -> {error, jid_not_found};
											_ -> {_PrivateData, UStorage} = eims:gen_summary(User, User),
												mnesia:dirty_write(UStorage#eims_storage{email = Email})
										end,
										{200, ok};
									_ ->
										{200, ok}
								end
						end;
					{ok, {{_, HttpCode, _}, _, Body}} = Res ->
						?dbg("ERROR: ~p", [Res]),
						{HttpCode, eims:decode_json(Body, <<"error">>)};
					{error, timeout} -> {408, timeout};
					Res ->
						?dbg("ERROR: ~p", [Res]),
						throw(invalid_request)
				end
			end;
		AuthNonce ->
			fun() -> {401, expired} end;
		_ ->
			fun() -> {403, forbidden} end
	end.

auth_post(#{jid := UserJid, pmuc := PMucJid, nick := Nick} = State) -> %%TODO maybe nick to add to pmuc?
	State2 = maps:remove(pmuc, State),
	try
		PMucJID = #jid{luser = PRoom, lserver = MucHost} = jid:decode(PMucJid),
		BareUserJid = jid:encode(jid:remove_resource(UserJID = jid:decode(UserJid))),
		Aff =
			case mod_muc_admin:get_room_affiliation(PRoom, MucHost, BareUserJid) of
				none ->
					mod_muc_admin:set_room_affiliation(PRoom, MucHost, BareUserJid, <<"member">>),
					member;
				A -> A
			end,
		Presence = #presence{from = UserJID, to = jid:replace_resource(PMucJID, Nick), sub_els = [#muc{}]},
		mod_muc:route(Presence),
		case Aff of
			member ->
				{ok, Pid} = mod_muc:unhibernate_room(eims:host(), MucHost, PRoom),
				mod_muc_room:change_item(Pid, UserJID, role, visitor, <<>>);
			_ -> ok
		end,
		mod_muc_admin:subscribe_room(UserJid, Nick, PMucJid, [?NS_MUCSUB_NODES_MESSAGES]),
		auth_post(State2#{text => <<"You enter to ", PMucJid/binary, " groupchat">>})
	catch
		{error, Reason} ->
			?err("~s", [Reason]),
			auth_post(State2#{text => iolist_to_binary(Reason)});
		E : R ->
			?err("~p : ~p", [E, R]),
			auth_post(State2#{text => <<"Internal error">>})
	end;
auth_post(#{jid := UserJid, groupchat := MucJid, text := Txt}) ->
	From = #jid{luser = Room, lserver = RoomHost} = jid:decode(MucJid),
	#jid{luser = LUser, lserver = LHost} = jid:decode(UserJid),
	[case jid:decode(Jid) of
		 #jid{luser = LUser, lserver = LHost} = JID ->
			 ejabberd_router:route(
				 #message{
					 type = groupchat,
					 from = jid:replace_resource(From, eims:bot_nick()),
					 to = JID,
					 body = [#text{data = Txt}]});
		 _ -> ok
	 end || {Jid, _Nick, _} <- mod_muc_admin:get_room_occupants(Room, RoomHost)];
auth_post(#{jid := _UserJid, groupchat := _MucJid} = State) ->
	auth_post(State#{text => <<"You successfully authorized with host service">>});
auth_post(_State) ->
	ok.

get_priv_data(Body) ->
	#{<<"result">> := #{<<"access_token">> := AccessToken, <<"refresh_token">> := RefreshToken}}
		= jiffy:decode(Body, [return_maps]),
	?dbg("new access_token: ~s", [AccessToken]),
	?dbg("new refresh_token: ~s", [RefreshToken]),
	#eims_auth{access_token = AccessToken, refresh_token = RefreshToken, time = eims:sys_time()}.

get_access_token(Jid) ->
	Now = eims:sys_time(),
	AccessTokenInterval = ?ACCESS_TOKEN_INTERVAL,
	case eims:get_tokens(Jid) of
		#eims_auth{time = Time, access_token = Token} when Now - Time < AccessTokenInterval * 1000 ->
			Token;
		#eims_auth{time = _Time} = AuthData ->
%%        #auth{time = Time} = AuthData when Now - Time < 899*1000 ->
			case eims:check_sync_hserv(fun() -> refresh_token(Jid, AuthData) end) of
				{_, #eims_auth{access_token = Token}} -> Token;
				Err -> Err
			end;
		_ ->
			{error, token_not_found}
	end.

send_delay_refresh(Data) ->
	send_delay_refresh(Data, ?REFRESH_TOKEN_INTERVAL * 1000).
send_delay_refresh({#jid{} = Jid, {Token, RefreshToken}}, Interval) ->
	send_delay_refresh({Jid, #eims_auth{access_token = Token, refresh_token = RefreshToken, time = eims:sys_time()}}, Interval);
send_delay_refresh({#jid{user = User, server = Server} = Jid, #eims_auth{access_token = Token, refresh_token = RefreshToken}} = Data, Interval) ->
	Json = jiffy:encode(#{<<"access_token">> => Token, <<"refresh_token">> => RefreshToken}),
	Payload = #message_payload{datatype = ?NS_TOKEN_TYPE, json = #payload_json{data = Json}},
	TokenPkt = #message{type = chat, from = jid:decode(eims:bot_component()), sub_els = [#hint{type = 'no-store'}, Payload]},
	[ejabberd_router:route(TokenPkt#message{to = jid:replace_resource(Jid, Resource)})
		|| Resource <- ejabberd_sm:get_user_resources(User, Server)],
	eims:send_delay_check(Data, refresh_token_fun(Jid, Interval), Interval).

refresh_token(#jid{} = Jid, #eims_auth{} = AuthData) ->
	(refresh_token_fun(Jid, ?REFRESH_TOKEN_INTERVAL * 1000))(AuthData).
refresh_token_fun(#jid{luser = _User, lserver = Host} = Jid, Interval) ->
	ConnOpts = eims:connection_opts(),
	#{Host := ISHost} = ConnOpts,
	fun(#eims_auth{refresh_token = RefreshToken}) ->
		?dbg("current refresh_token: ~s", [RefreshToken]),
		Url = uri_string:recompose(
			#{scheme => "https", host => ISHost, path => ?URI_AUTH,
			  query => uri_string:compose_query([{"grant_type", "refresh_token"}, {"refresh_token", RefreshToken}])}),
		request(get, {Url, []}, fun(Body) -> send_delay_refresh({Jid, get_priv_data(Body)}, Interval) end)
	end.

get_position_req(Jid, [InstrumentName]) ->
	private_request(Jid, ?URI_POSITION, [{"instrument_name", str:to_upper(InstrumentName)}]);
get_position_req(_Jid, Args) ->
	?dbg("get_position_req: invalid params: ~p", [Args]),
	{error, invalid_params}.

get_summary_req(Jid, [_Cur, Ext] = Args) when Ext == <<"true">>; Ext == <<"false">> ->
	private_request(Jid, ?URI_SUMMARY, lists:zip(["currency", "extended"], Args));
get_summary_req(_Jid, Args) ->
	?dbg("get_summary_req: invalid params: ~p", Args),
	{error, invalid_params}.

get_stats_req(Jid, [_Cur] = Args) ->
	private_request(Jid, ?URI_STATS, lists:zip(["currency"], Args));
get_stats_req(_Jid, Args) ->
	?dbg("get_stats_req: invalid params: ~p", Args),
	{error, invalid_params}.

get_account_summary_req(#jid{} = Jid) ->
	private_request(Jid, ?URI_ACCOUNT_SUMMARY, []);
get_account_summary_req(Token) ->
	private_request(?HOST, ?URI_ACCOUNT_SUMMARY, [], Token).
get_account_summary_req(Jid, Token) ->
	private_request(Jid, ?URI_ACCOUNT_SUMMARY, [], Token).

get_trade_volumes_req(#jid{lserver = _Host} = Jid) ->
	get_trade_volumes_req(Jid, <<"false">>).
get_trade_volumes_req(#jid{lserver = _Host}, Extended) ->
%%	check_request(get, Host, ?URI_TV, [], []).
	check_request(get, {hserv_host, eims:hservice_host()}, ?URI_TRADE_VOLUMES, [{<<"extended">>, Extended}], []). %% TODO temporary. Get itegrated service host from ejabberd.yml



private_request(_Jid, _Uri, _Args, Err) when element(1, Err) == error ->
	Err;
private_request(#jid{lserver = Host}, Uri, Args, Token) ->
	private_request(Host, Uri, Args, Token);
private_request(Host, Uri, Args, Token) ->
	?dbg("private_request(~p, ~p, ~p, ~p)", [Host, Uri, Args, Token]),
	Headers = [{"Authorization", "bearer " ++ binary_to_list(Token)}],
	check_request(get, Host, Uri, Args, Headers).
private_request(#jid{} = Jid, Uri, Args) ->
	case get_access_token(Jid) of
		Err when element(1, Err) == error ->
			?dbg("~p,~p: ~s: ~p", [?MODULE, ?LINE, jid:encode(Jid), Err]),
			Err;
		Token ->
			private_request(Jid, Uri, Args, Token)
	end.

check_request(get, {hserv_host, ISHost}, Uri, Args, Headers) ->
	Url = uri_string:normalize(#{scheme => "https", host => ISHost,
		path => Uri, query => uri_string:compose_query(Args)}),
	check_request({Url, Headers}, get);
check_request(get, Host, Uri, Args, Headers) ->
	#{Host := ISHost} = eims:connection_opts(),
	check_request(get, {hserv_host, ISHost}, Uri, Args, Headers).
check_request(Request) ->
	check_request(Request, get).
check_request(Request, Method) ->
	eims:check_sync_hserv(fun() -> request(Method, Request) end).

request(Method, Request) ->
	request(Method, Request, fun(Body) -> {ok, 200, eims:decode_json(Body)} end).
request(Method, Request, SuccessFun) ->
	case httpc:request(Method, Request, ?HTTP_OPTS, []) of
		{ok, {{_, 200, _}, _, Body}} ->
			SuccessFun(Body);
		{ok, {{_, _HttpCode, _}, _, Body}} = _Res ->
			case catch jiffy:decode(Body, [return_maps]) of
				#{} = Error ->
					?err("BAD REQUEST: ~p", [Body]),
					{error, bad_request, Error};
				{'EXIT', Reason} ->
					?err("INVALID REQUEST: ~p", [Reason]),
					{error, bad_request}
			end;
		Res ->
			?err("BAD REQUEST: ~p", [Res]),
			{error, bad_request}
	end.

-module(banword_gen_server).

-behaviour(gen_server).

-include("logger.hrl").

-export([member/1]).

%% gen_server callbacks
-export([start/1, stop/1, init/1, handle_call/3, handle_cast/2, handle_info/2, check_banword_only/2, check_banword/2, serverName/1,
  terminate/2, code_change/3, reload/1]).

serverName(Lang) ->
  list_to_atom(lists:flatten([atom_to_list(?MODULE), "_", atom_to_list(Lang)])).

reload(Lang) ->
  gen_server:call(serverName(Lang), {reload, Lang}).

member({Lang, Word} = _MessageToken) ->
  gen_server:call(serverName(Lang), {member, Word}).

start({Lang, BlacklistFile} = _Opts) ->
  Name = serverName(Lang),
  ?INFO_MSG("Building blacklist name ~p~n", [Name]),
  gen_server:start_link({local, serverName(Lang)}, ?MODULE, [BlacklistFile], []).

stop({Lang, _CharMapFile} = _Opts) ->
  gen_server:stop(serverName(Lang)).

readlines(FileName) ->
  {ok, Data} = file:read_file(FileName),
  BinList = binary:split(Data, [<<"\n">>], [global]),
  [string:strip(binary_to_list(X), right, $\r) || X <- BinList].

init([BlacklistFile]) ->
  ?INFO_MSG("Building blacklist ~p~n", [BlacklistFile]),
  {ok, loadWordList(BlacklistFile)}.

check_banword_only(Word, BlackWord) ->
  case string:lexemes(Word, ".!:;'\",?#$&^") of [BlackWord | _] -> true; _ -> false end.
check_banword(Word, BlackWord) ->
  try
    % ?INFO_MSG("== CHECK == ~p ~p~n", [Word, BlackWord]),
    string:rstr(Word, BlackWord) > 0
  catch _ ->
    false
  end.

handle_call({member, Word}, _From, BlackList) ->
  % ?INFO_MSG("~p ~p~n", [Word, BlackList]),
  Host = eims:host(),
  CheckFun = gen_mod:get_module_opt(Host, mod_pottymouth, check_fun),
  lists:foreach(
    fun(Elem) ->
      Res = ?MODULE:CheckFun(Word, Elem),
      if
        Res ->
          throw({reply, true, BlackList});
        true ->
          false
      end
    end, BlackList),
  {reply, false, BlackList};
handle_call({reload, Lang}, _From, BlackList) ->
  BlackLists = gen_mod:get_module_opt(global, mod_pottymouth, blacklists),
  {Res, BL} =
    case lists:keyfind(Lang, 1, BlackLists) of
      {_, PathFile} ->
        {ok, loadWordList(atom_to_list(PathFile))};
      false ->
        ?DEBUG("file ~p not found", []),
        {error_not_found, BlackList}
    end,
  % ?INFO_MSG("~p ~p~n", [Word, BlackList]),
  {reply, Res, BL}.

handle_cast(_Msg, State) -> {noreply, State}.
handle_info(_Info, State) -> {noreply, State}.
terminate(_Reason, _State) -> ok.
code_change(_OldVsn, State, _Extra) -> {ok, State}.

loadWordList(BlacklistFile) ->
  BlacklistExists = filelib:is_file(BlacklistFile),
  if
    BlacklistExists ->
      readlines(BlacklistFile);
    true ->
      ?ERROR_MSG("Blacklist file not found: ~p~n", [BlacklistFile]),
      []
  end.
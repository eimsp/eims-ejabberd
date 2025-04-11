-module(eims_api_codec).
-compile(export_all).

%% API
-include("eims_api_codec.hrl").
-include("eims.hrl").

decode(<<>>) ->
	more;
decode(<<"{", _/binary>> = Data) ->
	UsIn = erlang:system_time(microsecond),
	case catch jiffy:decode(Data, [return_maps]) of
		#{<<"result">> := _} = Map -> decode_result(Map);
		#{<<"error">> := _} = Map -> decode_error(Map);
		#{<<"params">> := _} = Map -> decode_pkt(Map#{<<"usIn">> => UsIn});
		{'EXIT', _} -> #packet_error{code = -32700, message = <<"Parse error">>, usIn = UsIn};
		_ -> #packet_error{code = -32602, message = <<"Invalid params">>, usIn = UsIn}
	end;
decode(_) ->
	#packet_error{code = -32700, message = <<"Parse error">>}.

decode_pkt(#{} = Map) ->
	case rfq_validator:packet_check(Map) of
		ok ->
			#{<<"method">> := Method, <<"params">> := Params, <<"usIn">> := UsIn} = Map,
			Id = case Map of #{<<"id">> := ID} -> ID; _ -> 0 end,
			decode_params(#packet{id = Id, method = Method, params = Params, usIn = UsIn});
		{error, Reason} ->
			ErrPkt = #packet_error{data = #{<<"reason">> => iolist_to_binary(Reason)}, usIn = erlang:system_time(microsecond)},
			case re:run(Reason, ".+\\snot\\sfound") of
				nomatch -> ErrPkt#packet_error{code = -32602, message = <<"Invalid params">>};
				_ -> ErrPkt#packet_error{code = -32000, message = <<"Missing params">>}
			end
	end.

decode_params(#packet{usIn = 0} = Pkt) ->
	decode_params(Pkt#packet{usIn = erlang:system_time(microsecond)});
decode_params(#packet{method = ?SUBSCRIPTION} = Pkt) ->
	{ok, Pkt};
decode_params(#packet{method = Method, type = []} = Pkt) ->
	ErrPkt = (packet_error(Pkt))#packet_error{code = -32601, message = <<"Method not found">>,
		data = #{<<"reason">> => <<"Method '", Method/binary, "' not found">>}},
	case binary:split(Method, <<"/">>) of
		[Type, _Name] when Type == <<"public">>; Type == <<"private">> ->
			case lists:member(Method, ?METHODS) of
				true -> decode_params(Pkt#packet{type = binary_to_atom(Type)});
				_ -> ErrPkt
			end;
		_ -> ErrPkt
	end;
decode_params(#packet{method =  Method, params = Params} = Pkt) ->
	CheckFunName = binary_to_atom(iolist_to_binary(tl(binary:split(Method, <<"/">>)) ++ ["_params_check"])),
	case rfq_validator:CheckFunName(Params) of
		ok -> {ok, Pkt};
		{error, Reason} ->
			(packet_error(Pkt))#packet_error{code = 11029, message = <<"invalid_arguments">>, data = #{<<"reason">> => iolist_to_binary(Reason)}}
	end.

decode_error(#{<<"id">> := Id, <<"error">> := #{<<"code">> := Code, <<"message">> := Message} = Err}) ->
	ErrPkt = case Err of #{<<"data">> := Data} -> #packet_error{data = Data}; _ -> #packet_error{} end,
	{ok, ErrPkt#packet_error{id = Id, code = Code, message = Message}};
decode_error(#{} = Map) -> %% TODO apply validator
	?err("WS INVALID PACKET: ~p", [Map]),
	{error, invalid_pkt}.

decode_result(#{<<"id">> := Id, <<"result">> := Result}) ->
	{ok, #packet_result{id = Id, result = Result}};
decode_result(#{<<"result">> := _Result} = Map) ->
	decode_result(Map#{<<"id">> => 0});
decode_result(#{} = Map) -> %% TODO apply validator
	?err("WS INVALID PACKET: ~p", [Map]),
	{error, invalid_pkt}.


encode_json(#{} = Map) ->
	case catch jiffy:encode(Map#{<<"testnet">> => gen_mod:get_module_opt(global, mod_eims, testnet)}) of
		{'EXIT', Reason} ->
			?err("invalid packet encode: ~p\n~p", [Map, Reason]),
			{error, invalid_packet};
		Json -> {ok, Json}
	end.

encode_pkt(#packet{id = 0, method = Method, params = Params} = Pkt) ->
	encode_pkt(#{method => Method, params => Params}, Pkt);
encode_pkt(#packet{id = Id, method = Method, params = Params} = Pkt) ->
	encode_pkt(#{id => Id, method => Method, params => Params}, Pkt);
encode_pkt(#packet_result{id = 0, result = Result} = Pkt) ->
	encode_pkt(#{result => Result}, Pkt);
encode_pkt(#packet_result{id = Id, result = Result} = Pkt) ->
	encode_pkt(#{id => Id, result => Result}, Pkt);
encode_pkt(#packet_error{id = Id, code = Code, message = Message, data = Data} = Pkt) ->
	encode_pkt(#{id => Id, <<"error">> => #{code => Code, message => Message, data => Data}}, Pkt);
encode_pkt(Pkt) ->
	?err("invalid packet encode: ~p", [Pkt]),
	{error, invalid_encode}.

encode_pkt(#{} = Map, Pkt) when is_record(Pkt, packet_result); is_record(Pkt, packet_error) ->
	UsIn = element(#packet_result.usIn, Pkt),
	UsOut = erlang:system_time(microsecond),
	encode_json(Map#{<<"usIn">> => UsIn, <<"usOut">> => UsOut, <<"usDiff">> => UsOut - UsIn});
encode_pkt(#{} = Map, _Pkt) ->
	encode_json(Map).

sys_time() ->
	erlang:system_time(microsecond).

packet_error(#packet{id = Id, time_ref = TRef, usIn = UsIn}) ->
	#packet_error{id = Id, time_ref = TRef, usIn = UsIn}.

packet_result(#packet{id = Id, time_ref = TRef, usIn = UsIn}) ->
	#packet_result{id = Id, time_ref = TRef, usIn = UsIn}.

packet_result(#packet{id = 0} = Pkt, #{} = Params) ->
	Pkt#packet{method = <<"subscription">>, params = Params};
packet_result(#packet{} = Pkt, #{} = Result) ->
	(packet_result(Pkt))#packet_result{result = Result}.

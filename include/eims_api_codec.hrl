-ifndef(EIMS_API_HRL).
-define(EIMS_API_HRL, true).

-record(packet, {id = 0 :: integer(),
				time_ref  :: undefined | timer:tref(),
				usIn = 0 :: timer:time(),
				method = <<>> :: binary(),
				params = #{} :: map() | list(binary()), %% TODO implement fix_transform for map() | ...
				type = [] :: private | public}).
-record(packet_result, {id = 0 :: integer(),
						time_ref :: undefined | timer:tref(),
						usIn = 0 :: timer:time(),
						result = #{} :: map() | binary()}).
-record(packet_error, {id = 0 :: integer(),
	                   time_ref :: undefined | timer:tref(),
					   usIn = 0 :: timer:time(),
					   code = 0 :: integer(),
					   data = #{} :: map(),
					   message = <<>> :: binary()}).


-type packet() :: #{id => nil() | number(), method => binary(), params => map() | [binary()]}.
-type err() :: #{code => number(), message => binary(), data => nil() | map()}.
-type packet_error() :: #{id => number(), error => err()}.

-type set_heartbeat_params() :: #{interval => number()}.
-type disable_heartbeat_params() :: #{}.
-type heartbeat_params() :: #{type => binary()}.
-type test_params() :: #{expected_result => nil() | map()}.
-type auth_params() :: #{'access_token' => binary(), refresh_token => binary()}.
-type get_market_places_params() :: #{}.
%%-type channels_params() :: #{}.
-type rfq_req_params() :: #{channel => binary()}.
%%-type rfq_req_params() :: #{channels => [binary()]}.
-type counterparties_params() :: #{channel => binary()}.
-type quote_request_params() :: #{channel => binary(), data => map()}.
-type quote_params() :: #{channel => binary(), data => map()}.
-type new_order_params() :: #{channel => binary(), data => map()}.
-type new_order_mleg_params() :: #{channel => binary(), data => [binary()]}.
-type execution_ack_params() :: #{channel => binary(), data => [binary()]}.
-type quotack_params() :: #{channel => binary(), data => [binary()]}.
-type quote_cancel_params() :: #{channel => binary(), data => [binary()]}.
-type quote_request_rej_params() :: #{channel => binary(), data => [binary()]}.
-type order_cancel_req_params() :: #{channel => binary(), data => [binary()]}.

-define(SET_HEARTBEAT       , <<"public/set_heartbeat">>).
-define(DISABLE_HEARTBEAT   , <<"public/disable_heartbeat">>).
-define(HEARTBEAT           , <<"public/heartbeat">>). %% TODO to make simply "heartbeat"
-define(DERIBIT_TEST        , <<"public/test">>).
-define(AUTH                , <<"public/auth">>).
-define(GET_MARKET_PLACES   , <<"public/get_market_places">>).
-define(RFQ_REQ             , <<"private/rfq_req">>).
-define(COUNTERPARTIES      , <<"public/counterparties">>).
-define(QUOTE_REQUEST       , <<"private/quote_request">>).
-define(QUOTE               , <<"private/quote">>).
-define(NEW_ORDER           , <<"private/new_order">>).
-define(NEW_ORDER_MLEG      , <<"private/new_order_mleg">>).
-define(EXECUTION_ACK       , <<"private/execution_ack">>).
-define(QUOTACK             , <<"private/quotack">>).
-define(QUOTE_CANCEL        , <<"private/quote_cancel">>).
-define(QUOTE_REQUEST_REJ   , <<"private/quote_request_rej">>).
-define(ORDER_CANCEL_REQ    , <<"private/order_cancel_req">>).
-define(SUBSCRIPTION        , <<"subscription">>).

-define(METHODS,
	[?SET_HEARTBEAT,
	?DISABLE_HEARTBEAT,
	?HEARTBEAT,
	?DERIBIT_TEST,
	?AUTH,
	?GET_MARKET_PLACES,
	?COUNTERPARTIES,
	?RFQ_REQ,
	?QUOTE_REQUEST,
	?QUOTE,
	?NEW_ORDER,
	?NEW_ORDER_MLEG,
	?EXECUTION_ACK,
	?QUOTACK,
	?QUOTE_CANCEL,
	?QUOTE_REQUEST_REJ,
	?ORDER_CANCEL_REQ]).

-endif.
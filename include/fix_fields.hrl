-ifndef(FIX_FIELDS_HRL).
-define(FIX_FIELDS_HRL, true).

-record(fix_field, {fix_name = [] :: binary(), iserv_name = [] :: binary(), tag = [] :: integer(), datatype = binary}).

-type quote_req_leg() :: #{'LegPrice' => nil() | number(),
							'LegSymbol' => binary(),
							'LegOrderQty' => number(),
							'LegSide' => nil() | buy | sell,
							'LegCurrency' => nil() | binary()}.
-type quote_req() :: #{'Parties' => [binary()],
						'BTReportInst' => nil() | 'Taker' | 'Maker',
						'PreTradeAnonymity' => nil() | boolean(), %% optional if nil
						'QuotReqLegsGrp' => nil() | [quote_req_leg()]}.
-type quote_leg() :: #{'LegPrice' => nil() | number(),
							'LegOfferPx' => nil() | number(),
							'LegBidPx' => nil() | number(),
							'LegSymbol' => binary(),
							'LegOrderQty' => number(),
							'LegSide' => nil() | buy | sell,
							'LegCurrency' => nil() | binary()}.
-type quote() :: #{'QuoteID' => nil() | binary(),
					'Parties' => nil() | [binary()],
					'PreTradeAnonymity' => nil() | boolean(), %% optional if nil
					'QuoteType' => nil() | 'RT' | 'TwoWay' | 'T',
					'LegQuotGrp' => [quote_leg()]}.

-type order() :: #{'QuoteID' => nil() | binary(),
					'Parties' => [binary()],
					'PreTradeAnonymity' => nil() | boolean(), %% optional if nil
					'LegOrdGrp' => nil() | [quote_req_leg()],
					'Text'	=> nil() | binary()}.

-type execution_ack() :: #{'ClOrdID' => number(),
														'ExecAckStatus' => nil() | boolean()}.


-endif.
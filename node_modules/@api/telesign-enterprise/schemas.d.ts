declare const GetSmsVerifyStatus: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly reference_id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                };
            };
            readonly required: readonly ["reference_id"];
        }, {
            readonly type: "object";
            readonly properties: {
                readonly verify_code: {
                    readonly type: "string";
                    readonly examples: readonly ["57244"];
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "If Telesign generated the code sent to your end user, include the asserted verification code from your end user here. ";
                };
            };
            readonly required: readonly [];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly title: "getStatusResponse";
            readonly required: readonly ["reference_id", "sub_resource", "errors", "status"];
            readonly properties: {
                readonly reference_id: {
                    readonly type: "string";
                    readonly description: "A unique, randomly generated hex value that identifies your web service request.";
                };
                readonly sub_resource: {
                    readonly type: "string";
                    readonly description: "The subresource accessed for the request. This is always `sms` for the SMS Verify API.";
                };
                readonly errors: {
                    readonly type: "array";
                    readonly description: "Contains an object for each error condition that resulted from the request.";
                    readonly items: {
                        readonly type: "object";
                        readonly title: "errorObject";
                        readonly description: "Contains properties related to an error that occurred during processing of the request.";
                        readonly properties: {
                            readonly code: {
                                readonly type: "integer";
                                readonly description: "A numeric code specifying which error occurred.";
                                readonly examples: readonly [-10001];
                            };
                            readonly description: {
                                readonly type: "string";
                                readonly description: "Text describing the error that occurred.";
                                readonly examples: readonly ["Invalid Request: PhoneNumber Parameter"];
                            };
                        };
                    };
                };
                readonly status: {
                    readonly type: "object";
                    readonly description: "Contains details about the request status.";
                    readonly required: readonly ["code", "description", "updated_on"];
                    readonly properties: {
                        readonly code: {
                            readonly type: "integer";
                            readonly description: "A numeric code indicating the processing status of this request.";
                        };
                        readonly description: {
                            readonly type: "string";
                            readonly description: "Text describing the transaction status.";
                        };
                        readonly updated_on: {
                            readonly type: "string";
                            readonly description: "An <a href=\"http://www.ietf.org/rfc/rfc3339.txt\">RFC 3339</a> timestamp indicating when the transaction status was updated.";
                        };
                    };
                };
                readonly verify: {
                    readonly type: "object";
                    readonly description: "Contains properties about the status of the verification attempt by the end user (if any).";
                    readonly properties: {
                        readonly code_state: {
                            readonly type: "string";
                            readonly description: "Indicates whether the verification code you provided in your request matches that sent by Telesign to the end-user. Possible values are: \n* `VALID` - The codes match. \n* `INVALID` - The codes do not match.\n* `EXPIRED` - The match was attempted after the end of the validity period for the code.\n* `MAX_ATTEMPTS_EXCEEDED` - The match was attempted after the end user already had made the maximum allowed number of attempts for the code.\n* `UNKNOWN` - Any other state.\n\n`VALID` `INVALID` `UNKNOWN` `EXPIRED` `MAX_ATTEMPTS_EXCEEDED`";
                            readonly enum: readonly ["VALID", "INVALID", "UNKNOWN", "EXPIRED", "MAX_ATTEMPTS_EXCEEDED"];
                            readonly examples: readonly ["VALID"];
                        };
                        readonly code_entered: {
                            readonly type: "string";
                            readonly description: "If the end user entered a code, what they entered is provided here.";
                            readonly examples: readonly ["45558"];
                        };
                    };
                };
                readonly additional_info: {
                    readonly type: "object";
                    readonly title: "additionalInfo";
                    readonly description: "Contains properties relevant when the message sent with this transaction is one of several parts of a longer message that was split. This object only appears if this feature is enabled for your account. Contact our [Customer Support Team](mailto:support@telesign.com) to request this feature.";
                    readonly properties: {
                        readonly message_part_sequence_number: {
                            readonly type: "integer";
                            readonly description: "Indicates this message's position in the series of split parts.";
                            readonly examples: readonly [1];
                        };
                        readonly message_parts_count: {
                            readonly type: "integer";
                            readonly description: "The total number of split parts for the longer message. If the message is not split, this value is `1`.";
                            readonly examples: readonly [2];
                        };
                        readonly message_parts_reference_ids: {
                            readonly type: "string";
                            readonly description: "The reference IDs for each part of the longer message, separated by commas.";
                            readonly examples: readonly ["35E63E88CB000E049196AD1CFCFFB89C,35E63E88CC7C050491613443467F3F12"];
                        };
                    };
                };
                readonly sim_swap: {
                    readonly type: "object";
                    readonly title: "SIMSwapResponse";
                    readonly description: "Properties related to the SIM Swap check for this transaction. This is only included if enabled by our [Customer Support Team](mailto:support@telesign.com).";
                    readonly properties: {
                        readonly swap_date: {
                            readonly type: "string";
                            readonly description: "The date of the SIM swap, if one is detected. ";
                            readonly examples: readonly ["2018-09-05"];
                        };
                        readonly swap_time: {
                            readonly type: "string";
                            readonly description: "The time of the SIM swap, if one is detected. ";
                            readonly examples: readonly ["22:00:00"];
                        };
                        readonly risk_indicator: {
                            readonly type: "integer";
                            readonly description: "Indicates the likelihood that a SIM swap occured for this number. The response ranges between `1` and `4`.\n* `1` - **(very low)** Swap did not occur or it occurred 15+ days ago. \n* `2` - **(low)** Swap occurred between 3 and 14 days ago. \n* `3` - **(medium)** Swap occurred in the last 72 hours. \n* `4` - **(high)** Swap occurred in the last 24 hours.";
                            readonly examples: readonly [1];
                        };
                        readonly status: {
                            readonly type: "object";
                            readonly description: "Contains properties related to the status of the SIM Swap check.";
                            readonly properties: {
                                readonly code: {
                                    readonly type: "integer";
                                    readonly description: "A code indicating the status of your request. ";
                                    readonly examples: readonly [2800];
                                };
                                readonly description: {
                                    readonly type: "string";
                                    readonly description: "Description of the status of your request.";
                                    readonly examples: readonly ["Request successfully completed"];
                                };
                            };
                        };
                    };
                };
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
        readonly "400": {
            readonly type: "object";
            readonly title: "getStatusResponse";
            readonly properties: {
                readonly reference_id: {
                    readonly type: "string";
                    readonly description: "A unique, randomly generated hex value that identifies your web service request.";
                };
                readonly sub_resource: {
                    readonly type: "string";
                    readonly description: "The subresource accessed for the request. This is always `sms` for the SMS Verify API.";
                };
                readonly errors: {
                    readonly type: "array";
                    readonly description: "Contains an object for each error condition that resulted from the request.";
                    readonly items: {
                        readonly type: "object";
                        readonly title: "errorObject";
                        readonly description: "Contains properties related to an error that occurred during processing of the request.";
                        readonly properties: {
                            readonly code: {
                                readonly type: "integer";
                                readonly description: "A numeric code specifying which error occurred.";
                                readonly examples: readonly [-10001];
                            };
                            readonly description: {
                                readonly type: "string";
                                readonly description: "Text describing the error that occurred.";
                                readonly examples: readonly ["Invalid Request: PhoneNumber Parameter"];
                            };
                        };
                    };
                };
                readonly status: {
                    readonly type: "object";
                    readonly description: "Contains details about the request status.";
                    readonly required: readonly ["code", "description", "updated_on"];
                    readonly properties: {
                        readonly code: {
                            readonly type: "integer";
                            readonly description: "A numeric code indicating the processing status of this request.";
                        };
                        readonly description: {
                            readonly type: "string";
                            readonly description: "Text describing the transaction status.";
                        };
                        readonly updated_on: {
                            readonly type: "string";
                            readonly description: "An <a href=\"http://www.ietf.org/rfc/rfc3339.txt\">RFC 3339</a> timestamp indicating when the transaction status was updated.";
                        };
                    };
                };
                readonly verify: {
                    readonly type: "object";
                    readonly description: "Contains properties about the status of the verification attempt by the end user (if any).";
                    readonly properties: {
                        readonly code_state: {
                            readonly type: "string";
                            readonly description: "Indicates whether the verification code you provided in your request matches that sent by Telesign to the end-user. Possible values are: \n* `VALID` - The codes match. \n* `INVALID` - The codes do not match.\n* `EXPIRED` - The match was attempted after the end of the validity period for the code.\n* `MAX_ATTEMPTS_EXCEEDED` - The match was attempted after the end user already had made the maximum allowed number of attempts for the code.\n* `UNKNOWN` - Any other state.\n\n`VALID` `INVALID` `UNKNOWN` `EXPIRED` `MAX_ATTEMPTS_EXCEEDED`";
                            readonly enum: readonly ["VALID", "INVALID", "UNKNOWN", "EXPIRED", "MAX_ATTEMPTS_EXCEEDED"];
                            readonly examples: readonly ["VALID"];
                        };
                        readonly code_entered: {
                            readonly type: "string";
                            readonly description: "If the end user entered a code, what they entered is provided here.";
                            readonly examples: readonly ["45558"];
                        };
                    };
                };
                readonly additional_info: {
                    readonly type: "object";
                    readonly title: "additionalInfo";
                    readonly description: "Contains properties relevant when the message sent with this transaction is one of several parts of a longer message that was split. This object only appears if this feature is enabled for your account. Contact our [Customer Support Team](mailto:support@telesign.com) to request this feature.";
                    readonly properties: {
                        readonly message_part_sequence_number: {
                            readonly type: "integer";
                            readonly description: "Indicates this message's position in the series of split parts.";
                            readonly examples: readonly [1];
                        };
                        readonly message_parts_count: {
                            readonly type: "integer";
                            readonly description: "The total number of split parts for the longer message. If the message is not split, this value is `1`.";
                            readonly examples: readonly [2];
                        };
                        readonly message_parts_reference_ids: {
                            readonly type: "string";
                            readonly description: "The reference IDs for each part of the longer message, separated by commas.";
                            readonly examples: readonly ["35E63E88CB000E049196AD1CFCFFB89C,35E63E88CC7C050491613443467F3F12"];
                        };
                    };
                };
            };
            readonly required: readonly ["reference_id", "sub_resource", "errors", "status"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
        readonly "401": {
            readonly type: "object";
            readonly title: "getStatusResponse";
            readonly required: readonly ["reference_id", "sub_resource", "errors", "status"];
            readonly properties: {
                readonly reference_id: {
                    readonly type: "string";
                    readonly description: "A unique, randomly generated hex value that identifies your web service request.";
                };
                readonly sub_resource: {
                    readonly type: "string";
                    readonly description: "The subresource accessed for the request. This is always `sms` for the SMS Verify API.";
                };
                readonly errors: {
                    readonly type: "array";
                    readonly description: "Contains an object for each error condition that resulted from the request.";
                    readonly items: {
                        readonly type: "object";
                        readonly title: "errorObject";
                        readonly description: "Contains properties related to an error that occurred during processing of the request.";
                        readonly properties: {
                            readonly code: {
                                readonly type: "integer";
                                readonly description: "A numeric code specifying which error occurred.";
                                readonly examples: readonly [-10001];
                            };
                            readonly description: {
                                readonly type: "string";
                                readonly description: "Text describing the error that occurred.";
                                readonly examples: readonly ["Invalid Request: PhoneNumber Parameter"];
                            };
                        };
                    };
                };
                readonly status: {
                    readonly type: "object";
                    readonly description: "Contains details about the request status.";
                    readonly required: readonly ["code", "description", "updated_on"];
                    readonly properties: {
                        readonly code: {
                            readonly type: "integer";
                            readonly description: "A numeric code indicating the processing status of this request.";
                        };
                        readonly description: {
                            readonly type: "string";
                            readonly description: "Text describing the transaction status.";
                        };
                        readonly updated_on: {
                            readonly type: "string";
                            readonly description: "An <a href=\"http://www.ietf.org/rfc/rfc3339.txt\">RFC 3339</a> timestamp indicating when the transaction status was updated.";
                        };
                    };
                };
                readonly verify: {
                    readonly type: "object";
                    readonly description: "Contains properties about the status of the verification attempt by the end user (if any).";
                    readonly properties: {
                        readonly code_state: {
                            readonly type: "string";
                            readonly description: "Indicates whether the verification code you provided in your request matches that sent by Telesign to the end-user. Possible values are: \n* `VALID` - The codes match. \n* `INVALID` - The codes do not match.\n* `EXPIRED` - The match was attempted after the end of the validity period for the code.\n* `MAX_ATTEMPTS_EXCEEDED` - The match was attempted after the end user already had made the maximum allowed number of attempts for the code.\n* `UNKNOWN` - Any other state.\n\n`VALID` `INVALID` `UNKNOWN` `EXPIRED` `MAX_ATTEMPTS_EXCEEDED`";
                            readonly enum: readonly ["VALID", "INVALID", "UNKNOWN", "EXPIRED", "MAX_ATTEMPTS_EXCEEDED"];
                            readonly examples: readonly ["VALID"];
                        };
                        readonly code_entered: {
                            readonly type: "string";
                            readonly description: "If the end user entered a code, what they entered is provided here.";
                            readonly examples: readonly ["45558"];
                        };
                    };
                };
                readonly additional_info: {
                    readonly type: "object";
                    readonly title: "additionalInfo";
                    readonly description: "Contains properties relevant when the message sent with this transaction is one of several parts of a longer message that was split. This object only appears if this feature is enabled for your account. Contact our [Customer Support Team](mailto:support@telesign.com) to request this feature.";
                    readonly properties: {
                        readonly message_part_sequence_number: {
                            readonly type: "integer";
                            readonly description: "Indicates this message's position in the series of split parts.";
                            readonly examples: readonly [1];
                        };
                        readonly message_parts_count: {
                            readonly type: "integer";
                            readonly description: "The total number of split parts for the longer message. If the message is not split, this value is `1`.";
                            readonly examples: readonly [2];
                        };
                        readonly message_parts_reference_ids: {
                            readonly type: "string";
                            readonly description: "The reference IDs for each part of the longer message, separated by commas.";
                            readonly examples: readonly ["35E63E88CB000E049196AD1CFCFFB89C,35E63E88CC7C050491613443467F3F12"];
                        };
                    };
                };
                readonly signature_string: {
                    readonly type: "string";
                    readonly description: "Returned when request signature is not valid. Signature from failed authorization requests - doesn’t contain all required data (like x-ts-auth-method), or it’s not ordered properly.";
                    readonly examples: readonly ["GET\\n\\nTue, 31 Jan 2024 19:36:42 GMT\\nx-ts-auth-method: HMAC-SHA256\\n/v1/verify/0123456789ABCDEF0123456789ABCDEF"];
                };
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
        readonly "404": {
            readonly type: "object";
            readonly title: "getStatusResponse";
            readonly properties: {
                readonly reference_id: {
                    readonly type: "string";
                    readonly description: "A unique, randomly generated hex value that identifies your web service request.";
                };
                readonly sub_resource: {
                    readonly type: "string";
                    readonly description: "The subresource accessed for the request. This is always `sms` for the SMS Verify API.";
                };
                readonly errors: {
                    readonly type: "array";
                    readonly description: "Contains an object for each error condition that resulted from the request.";
                    readonly items: {
                        readonly type: "object";
                        readonly title: "errorObject";
                        readonly description: "Contains properties related to an error that occurred during processing of the request.";
                        readonly properties: {
                            readonly code: {
                                readonly type: "integer";
                                readonly description: "A numeric code specifying which error occurred.";
                                readonly examples: readonly [-10001];
                            };
                            readonly description: {
                                readonly type: "string";
                                readonly description: "Text describing the error that occurred.";
                                readonly examples: readonly ["Invalid Request: PhoneNumber Parameter"];
                            };
                        };
                    };
                };
                readonly status: {
                    readonly type: "object";
                    readonly description: "Contains details about the request status.";
                    readonly required: readonly ["code", "description", "updated_on"];
                    readonly properties: {
                        readonly code: {
                            readonly type: "integer";
                            readonly description: "A numeric code indicating the processing status of this request.";
                        };
                        readonly description: {
                            readonly type: "string";
                            readonly description: "Text describing the transaction status.";
                        };
                        readonly updated_on: {
                            readonly type: "string";
                            readonly description: "An <a href=\"http://www.ietf.org/rfc/rfc3339.txt\">RFC 3339</a> timestamp indicating when the transaction status was updated.";
                        };
                    };
                };
                readonly verify: {
                    readonly type: "object";
                    readonly description: "Contains properties about the status of the verification attempt by the end user (if any).";
                    readonly properties: {
                        readonly code_state: {
                            readonly type: "string";
                            readonly description: "Indicates whether the verification code you provided in your request matches that sent by Telesign to the end-user. Possible values are: \n* `VALID` - The codes match. \n* `INVALID` - The codes do not match.\n* `EXPIRED` - The match was attempted after the end of the validity period for the code.\n* `MAX_ATTEMPTS_EXCEEDED` - The match was attempted after the end user already had made the maximum allowed number of attempts for the code.\n* `UNKNOWN` - Any other state.\n\n`VALID` `INVALID` `UNKNOWN` `EXPIRED` `MAX_ATTEMPTS_EXCEEDED`";
                            readonly enum: readonly ["VALID", "INVALID", "UNKNOWN", "EXPIRED", "MAX_ATTEMPTS_EXCEEDED"];
                            readonly examples: readonly ["VALID"];
                        };
                        readonly code_entered: {
                            readonly type: "string";
                            readonly description: "If the end user entered a code, what they entered is provided here.";
                            readonly examples: readonly ["45558"];
                        };
                    };
                };
                readonly additional_info: {
                    readonly type: "object";
                    readonly title: "additionalInfo";
                    readonly description: "Contains properties relevant when the message sent with this transaction is one of several parts of a longer message that was split. This object only appears if this feature is enabled for your account. Contact our [Customer Support Team](mailto:support@telesign.com) to request this feature.";
                    readonly properties: {
                        readonly message_part_sequence_number: {
                            readonly type: "integer";
                            readonly description: "Indicates this message's position in the series of split parts.";
                            readonly examples: readonly [1];
                        };
                        readonly message_parts_count: {
                            readonly type: "integer";
                            readonly description: "The total number of split parts for the longer message. If the message is not split, this value is `1`.";
                            readonly examples: readonly [2];
                        };
                        readonly message_parts_reference_ids: {
                            readonly type: "string";
                            readonly description: "The reference IDs for each part of the longer message, separated by commas.";
                            readonly examples: readonly ["35E63E88CB000E049196AD1CFCFFB89C,35E63E88CC7C050491613443467F3F12"];
                        };
                    };
                };
            };
            readonly required: readonly ["reference_id", "sub_resource", "errors", "status"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
        readonly "429": {
            readonly type: "object";
            readonly title: "getStatusResponse";
            readonly properties: {
                readonly reference_id: {
                    readonly type: "string";
                    readonly description: "A unique, randomly generated hex value that identifies your web service request.";
                };
                readonly sub_resource: {
                    readonly type: "string";
                    readonly description: "The subresource accessed for the request. This is always `sms` for the SMS Verify API.";
                };
                readonly errors: {
                    readonly type: "array";
                    readonly description: "Contains an object for each error condition that resulted from the request.";
                    readonly items: {
                        readonly type: "object";
                        readonly title: "errorObject";
                        readonly description: "Contains properties related to an error that occurred during processing of the request.";
                        readonly properties: {
                            readonly code: {
                                readonly type: "integer";
                                readonly description: "A numeric code specifying which error occurred.";
                                readonly examples: readonly [-10001];
                            };
                            readonly description: {
                                readonly type: "string";
                                readonly description: "Text describing the error that occurred.";
                                readonly examples: readonly ["Invalid Request: PhoneNumber Parameter"];
                            };
                        };
                    };
                };
                readonly status: {
                    readonly type: "object";
                    readonly description: "Contains details about the request status.";
                    readonly required: readonly ["code", "description", "updated_on"];
                    readonly properties: {
                        readonly code: {
                            readonly type: "integer";
                            readonly description: "A numeric code indicating the processing status of this request.";
                        };
                        readonly description: {
                            readonly type: "string";
                            readonly description: "Text describing the transaction status.";
                        };
                        readonly updated_on: {
                            readonly type: "string";
                            readonly description: "An <a href=\"http://www.ietf.org/rfc/rfc3339.txt\">RFC 3339</a> timestamp indicating when the transaction status was updated.";
                        };
                    };
                };
                readonly verify: {
                    readonly type: "object";
                    readonly description: "Contains properties about the status of the verification attempt by the end user (if any).";
                    readonly properties: {
                        readonly code_state: {
                            readonly type: "string";
                            readonly description: "Indicates whether the verification code you provided in your request matches that sent by Telesign to the end-user. Possible values are: \n* `VALID` - The codes match. \n* `INVALID` - The codes do not match.\n* `EXPIRED` - The match was attempted after the end of the validity period for the code.\n* `MAX_ATTEMPTS_EXCEEDED` - The match was attempted after the end user already had made the maximum allowed number of attempts for the code.\n* `UNKNOWN` - Any other state.\n\n`VALID` `INVALID` `UNKNOWN` `EXPIRED` `MAX_ATTEMPTS_EXCEEDED`";
                            readonly enum: readonly ["VALID", "INVALID", "UNKNOWN", "EXPIRED", "MAX_ATTEMPTS_EXCEEDED"];
                            readonly examples: readonly ["VALID"];
                        };
                        readonly code_entered: {
                            readonly type: "string";
                            readonly description: "If the end user entered a code, what they entered is provided here.";
                            readonly examples: readonly ["45558"];
                        };
                    };
                };
                readonly additional_info: {
                    readonly type: "object";
                    readonly title: "additionalInfo";
                    readonly description: "Contains properties relevant when the message sent with this transaction is one of several parts of a longer message that was split. This object only appears if this feature is enabled for your account. Contact our [Customer Support Team](mailto:support@telesign.com) to request this feature.";
                    readonly properties: {
                        readonly message_part_sequence_number: {
                            readonly type: "integer";
                            readonly description: "Indicates this message's position in the series of split parts.";
                            readonly examples: readonly [1];
                        };
                        readonly message_parts_count: {
                            readonly type: "integer";
                            readonly description: "The total number of split parts for the longer message. If the message is not split, this value is `1`.";
                            readonly examples: readonly [2];
                        };
                        readonly message_parts_reference_ids: {
                            readonly type: "string";
                            readonly description: "The reference IDs for each part of the longer message, separated by commas.";
                            readonly examples: readonly ["35E63E88CB000E049196AD1CFCFFB89C,35E63E88CC7C050491613443467F3F12"];
                        };
                    };
                };
            };
            readonly required: readonly ["reference_id", "sub_resource", "errors", "status"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
        readonly "503": {
            readonly type: "object";
            readonly title: "getStatusResponse";
            readonly properties: {
                readonly reference_id: {
                    readonly type: "string";
                    readonly description: "A unique, randomly generated hex value that identifies your web service request.";
                };
                readonly sub_resource: {
                    readonly type: "string";
                    readonly description: "The subresource accessed for the request. This is always `sms` for the SMS Verify API.";
                };
                readonly errors: {
                    readonly type: "array";
                    readonly description: "Contains an object for each error condition that resulted from the request.";
                    readonly items: {
                        readonly type: "object";
                        readonly title: "errorObject";
                        readonly description: "Contains properties related to an error that occurred during processing of the request.";
                        readonly properties: {
                            readonly code: {
                                readonly type: "integer";
                                readonly description: "A numeric code specifying which error occurred.";
                                readonly examples: readonly [-10001];
                            };
                            readonly description: {
                                readonly type: "string";
                                readonly description: "Text describing the error that occurred.";
                                readonly examples: readonly ["Invalid Request: PhoneNumber Parameter"];
                            };
                        };
                    };
                };
                readonly status: {
                    readonly type: "object";
                    readonly description: "Contains details about the request status.";
                    readonly required: readonly ["code", "description", "updated_on"];
                    readonly properties: {
                        readonly code: {
                            readonly type: "integer";
                            readonly description: "A numeric code indicating the processing status of this request.";
                        };
                        readonly description: {
                            readonly type: "string";
                            readonly description: "Text describing the transaction status.";
                        };
                        readonly updated_on: {
                            readonly type: "string";
                            readonly description: "An <a href=\"http://www.ietf.org/rfc/rfc3339.txt\">RFC 3339</a> timestamp indicating when the transaction status was updated.";
                        };
                    };
                };
                readonly verify: {
                    readonly type: "object";
                    readonly description: "Contains properties about the status of the verification attempt by the end user (if any).";
                    readonly properties: {
                        readonly code_state: {
                            readonly type: "string";
                            readonly description: "Indicates whether the verification code you provided in your request matches that sent by Telesign to the end-user. Possible values are: \n* `VALID` - The codes match. \n* `INVALID` - The codes do not match.\n* `EXPIRED` - The match was attempted after the end of the validity period for the code.\n* `MAX_ATTEMPTS_EXCEEDED` - The match was attempted after the end user already had made the maximum allowed number of attempts for the code.\n* `UNKNOWN` - Any other state.\n\n`VALID` `INVALID` `UNKNOWN` `EXPIRED` `MAX_ATTEMPTS_EXCEEDED`";
                            readonly enum: readonly ["VALID", "INVALID", "UNKNOWN", "EXPIRED", "MAX_ATTEMPTS_EXCEEDED"];
                            readonly examples: readonly ["VALID"];
                        };
                        readonly code_entered: {
                            readonly type: "string";
                            readonly description: "If the end user entered a code, what they entered is provided here.";
                            readonly examples: readonly ["45558"];
                        };
                    };
                };
                readonly additional_info: {
                    readonly type: "object";
                    readonly title: "additionalInfo";
                    readonly description: "Contains properties relevant when the message sent with this transaction is one of several parts of a longer message that was split. This object only appears if this feature is enabled for your account. Contact our [Customer Support Team](mailto:support@telesign.com) to request this feature.";
                    readonly properties: {
                        readonly message_part_sequence_number: {
                            readonly type: "integer";
                            readonly description: "Indicates this message's position in the series of split parts.";
                            readonly examples: readonly [1];
                        };
                        readonly message_parts_count: {
                            readonly type: "integer";
                            readonly description: "The total number of split parts for the longer message. If the message is not split, this value is `1`.";
                            readonly examples: readonly [2];
                        };
                        readonly message_parts_reference_ids: {
                            readonly type: "string";
                            readonly description: "The reference IDs for each part of the longer message, separated by commas.";
                            readonly examples: readonly ["35E63E88CB000E049196AD1CFCFFB89C,35E63E88CC7C050491613443467F3F12"];
                        };
                    };
                };
            };
            readonly required: readonly ["reference_id", "sub_resource", "errors", "status"];
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const ReportSmsVerifyCompletion: {
    readonly metadata: {
        readonly allOf: readonly [{
            readonly type: "object";
            readonly properties: {
                readonly reference_id: {
                    readonly type: "string";
                    readonly $schema: "http://json-schema.org/draft-04/schema#";
                    readonly description: "The reference ID for the transaction you want to provide completion data about.\n";
                };
            };
            readonly required: readonly ["reference_id"];
        }];
    };
    readonly response: {
        readonly "200": {
            readonly type: "object";
            readonly title: "putCompletionResponse";
            readonly properties: {
                readonly reference_id: {
                    readonly type: "string";
                    readonly description: "A unique, randomly generated hex value that identifies your web service request.";
                    readonly minLength: 32;
                    readonly maxLength: 32;
                };
                readonly subresource: {
                    readonly type: "string";
                    readonly description: "The subresource in the URI path from your original request to initiate this transaction. Indicates which form of verification you used.";
                    readonly examples: readonly ["sms"];
                };
                readonly errors: {
                    readonly type: "array";
                    readonly description: "Contains an object for each error condition that resulted from the request.";
                    readonly items: {
                        readonly type: "object";
                        readonly title: "errorObject";
                        readonly description: "Contains properties related to an error that occurred during processing of the request.";
                        readonly properties: {
                            readonly code: {
                                readonly type: "integer";
                                readonly description: "A numeric code specifying which error occurred.";
                                readonly examples: readonly [-10001];
                            };
                            readonly description: {
                                readonly type: "string";
                                readonly description: "Text describing the error that occurred.";
                                readonly examples: readonly ["Invalid Request: PhoneNumber Parameter"];
                            };
                        };
                    };
                };
                readonly status: {
                    readonly type: "object";
                    readonly description: "Contains details about the request status.";
                    readonly properties: {
                        readonly code: {
                            readonly type: "string";
                            readonly description: "A numeric code indicating the processing status of this request.";
                        };
                        readonly description: {
                            readonly type: "string";
                            readonly description: "A text description of the status code.";
                        };
                        readonly updated_on: {
                            readonly type: "string";
                            readonly description: "An [RFC 3339](http://www.ietf.org/rfc/rfc3339.txt) timestamp indicating when the request status was updated. ";
                        };
                    };
                    readonly required: readonly ["code", "description", "updated_on"];
                };
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
        readonly "400": {
            readonly type: "object";
            readonly title: "errorObject";
            readonly description: "Contains properties related to an error that occurred during processing of the request.";
            readonly properties: {
                readonly code: {
                    readonly type: "integer";
                    readonly description: "A numeric code specifying which error occurred.";
                    readonly examples: readonly [-10001];
                };
                readonly description: {
                    readonly type: "string";
                    readonly description: "Text describing the error that occurred.";
                    readonly examples: readonly ["Invalid Request: PhoneNumber Parameter"];
                };
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
        readonly "401": {
            readonly type: "object";
            readonly title: "errorObject";
            readonly description: "Contains properties related to an error that occurred during processing of the request.";
            readonly properties: {
                readonly code: {
                    readonly type: "integer";
                    readonly description: "A numeric code specifying which error occurred.";
                    readonly examples: readonly [-10001];
                };
                readonly description: {
                    readonly type: "string";
                    readonly description: "Text describing the error that occurred.";
                    readonly examples: readonly ["Invalid Request: PhoneNumber Parameter"];
                };
                readonly signature_string: {
                    readonly type: "string";
                    readonly description: "Returned when request signature is not valid. Signature from failed authorization requests - doesn’t contain all required data (like x-ts-auth-method), or it’s not ordered properly.";
                    readonly examples: readonly ["PUT\\n\\nTue, 31 Jan 2024 19:36:42 GMT\\nx-ts-auth-method: HMAC-SHA256\\n/v1/verify/completion/0123456789ABCDEF0123456789ABCDEF"];
                };
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
        readonly "404": {
            readonly type: "object";
            readonly title: "errorObject";
            readonly description: "Contains properties related to an error that occurred during processing of the request.";
            readonly properties: {
                readonly code: {
                    readonly type: "integer";
                    readonly description: "A numeric code specifying which error occurred.";
                    readonly examples: readonly [-10001];
                };
                readonly description: {
                    readonly type: "string";
                    readonly description: "Text describing the error that occurred.";
                    readonly examples: readonly ["Invalid Request: PhoneNumber Parameter"];
                };
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
        readonly "503": {
            readonly type: "object";
            readonly properties: {
                readonly status: {
                    readonly title: "statusObject";
                    readonly type: "object";
                    readonly description: "Contains properties related to the processing status of the transaction.";
                    readonly properties: {
                        readonly code: {
                            readonly type: "integer";
                            readonly description: "A numeric code that indicates the status of your transaction.";
                        };
                        readonly description: {
                            readonly type: "string";
                            readonly description: "Text describing the status of your transaction.";
                        };
                    };
                    readonly required: readonly ["code", "description"];
                };
                readonly error: {
                    readonly type: "object";
                    readonly title: "errorObject";
                    readonly description: "Contains properties related to an error that occurred during processing of the request.";
                    readonly properties: {
                        readonly code: {
                            readonly type: "integer";
                            readonly description: "A numeric code specifying which error occurred.";
                            readonly examples: readonly [-10001];
                        };
                        readonly description: {
                            readonly type: "string";
                            readonly description: "Text describing the error that occurred.";
                            readonly examples: readonly ["Invalid Request: PhoneNumber Parameter"];
                        };
                    };
                };
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
declare const SendSmsVerifyCode: {
    readonly formData: {
        readonly type: "object";
        readonly properties: {
            readonly phone_number: {
                readonly type: "string";
                readonly description: "The end user's phone number you want to send a message to, as digits without spaces or special characters, beginning with the country dialing code.";
                readonly examples: readonly ["15558675309"];
            };
            readonly ucid: {
                readonly type: "string";
                readonly description: "A code specifying the use case you are making the request for. Choices include:\n* `ATCK` - For use in a 2FA situation like updating an account or logging in.\n* `BACF` - For creating an account where the service may be vulnerable to bulk attacks and fraudsters.\n* `BACS` - For creating an account where the service may be vulnerable to bulk attacks or individual spammers.\n* `CHBK` - For use when someone is trying to buy something expensive or unusual and you want to verify it is really them.\n* `CLDR` - Calendar event.\n* `LEAD` - For use in a situation where you require a person to enter personal details to request information about a potential purchase (like a loan, real estate, or attending a school), and you want to check if they are legitimate.\n* `OTHR` - For a situation not addressed by other tags.\n* `PWRT` - For use in a situation where a password reset is required.\n* `RESV` - For use when you have end users making reservations, and you want to confirm they will show up.\n* `RXPF` - For use when you are trying to prevent prescription fraud.\n* `SHIP` - For use when you are sending a shipping notification.\n* `THEF` - For use when you are trying to prevent an end user from deactivating or redirecting a phone number for identity theft purposes.\n* `TRVF` - For use when you are transferring money and want to check if the transfer is approved by sending a text message to your end user. This is similar to `CHBK`, but is specifically for a money transaction.\n* `UNKN` - For a situation not addressed by other tags (same as `OTHR`).";
            };
            readonly originating_ip: {
                readonly type: "string";
                readonly description: "Your end user's IP address (do not send your own IP address). This is used to help Telesign improve our services. IPv4 and IPv6 are supported. For IPv4, the value must be in the format defined by the Internet Engineering Task Force (IETF) in the Internet-Draft document titled <a href=\"https://tools.ietf.org/html/rfc791\">Internet Protocol</a>. For IPv6, the value must be in the format defined by the IETF in the Internet-Draft document titled <a href=\"https://tools.ietf.org/html/rfc4291#section-2.2\">IP Version 6 Addressing Architecture</a>.";
            };
            readonly language: {
                readonly type: "string";
                readonly description: "A code specifying the language of the predefined template you wish to use. For a complete list of codes, see [SMS Verify API - Supported languages](/enterprise/docs/sms-verify-api-supported-languages). If you provide overriding message text in the `template` parameter, this field is not used.";
            };
            readonly verify_code: {
                readonly type: "string";
                readonly description: "The verification code used for the code challenge. By defauls, Telesign randomly generates a seven-digit numeric value for you. You can override the default behavior by including your own numeric code for this parameter, with a value between `000` and `9999999`. Only numeric characters are supported. Either way, the verification code replaces the variable `$$CODE$$` in the message template. ";
                readonly minLength: 3;
                readonly maxLength: 7;
                readonly examples: readonly ["57244"];
            };
            readonly template: {
                readonly type: "string";
                readonly description: "Text that overrides the contents of the predefined message templates. Include the `$$CODE$$` variable to have the verification code automatically inserted. For payment transactions, include the `$$AMOUNT$$` and `$$PAYEE$$` variables to have those payment details from your other params automatically inserted. By default, the maximum length of this field is 160 characters. Telesign recommends that you keep your messages brief if possible, but if you want to send longer messages contact our Customer Support Team to have the maximum increased. A long message may be up to 1600 characters.";
                readonly examples: readonly ["Your code is $$CODE$$"];
            };
            readonly sender_id: {
                readonly type: "string";
                readonly description: "Specifies the sender ID to be displayed to the end user on the SMS message. Before using this, give any sender IDs you might want to use to our Customer Support Team, so we can add them to our allow list. If the sender ID in this field is not on this list, it is not used. We do not guarantee that the sender ID you specify will be used; Telesign may override this value to improve delivery quality or to follow the SMS regulations of particular countries. We recommend limiting values to 0-9 and A-Z, as support for other ASCII characters varies by carrier.";
                readonly maxLength: 20;
            };
            readonly is_primary: {
                readonly type: "string";
                readonly description: "Whether you are using this service as your primary provider to send this message (`”true”`) or\"as a backup after your primary provider failed (`”false”`). We use this data to optimize message routing.";
                readonly default: "true";
            };
            readonly dlt_template_id: {
                readonly type: "string";
                readonly maxLength: 40;
                readonly description: "**(India-local traffic only)**. The ID of the DLT template used for this message. See [India DLT Update](https://support.telesign.com/s/article/India-DLT-Update) for more details on the relevant regulations.";
            };
            readonly dlt_entity_id: {
                readonly type: "string";
                readonly maxLength: 40;
                readonly description: "**(India-local traffic only)**. The ID of the entity sending this message. See [India DLT Update](https://support.telesign.com/s/article/India-DLT-Update) for more details on the relevant regulations.";
            };
            readonly transaction_amount: {
                readonly type: "string";
                readonly description: "**(Payment-transactions only)**  Replaces the `$$AMOUNT$$` variable in the message template. Specifies the currency and amount for the payment that the end user is approving. This parameter is required if `transaction_payee` is included in the request.";
                readonly maxLength: 40;
            };
            readonly transaction_payee: {
                readonly type: "string";
                readonly description: "**(Payment-transactions only)** Replaces the `$$PAYEE$$` variable in the message template. Specifies the entity that the end user is approving a payment to.\nThis parameter is required if `transaction_amount` is included in the request.";
                readonly maxLength: 40;
            };
            readonly sim_swap_check: {
                readonly type: "string";
                readonly description: "Set a value of `\"true\"` to screen this transaction using a Telesign SIM Swap check. This only has an effect if we have enabled SIM Swap for your account and configured it to be toggled using this parameter. If your account is configured to perform the check on every transaction, set a value of `\"false\"` to suppress the check. Contact our [Customer Support Team](mailto:support@telesign.com) to turn on this feature.";
                readonly maxLength: 40;
            };
            readonly callback_url: {
                readonly type: "string";
                readonly description: "A URL where you want delivery reports to be sent related to your request. This overrides any default callback URL that you’ve previously set. The override only lasts for this request.";
            };
        };
        readonly required: readonly ["phone_number"];
        readonly $schema: "http://json-schema.org/draft-04/schema#";
    };
    readonly response: {
        readonly "200": {
            readonly title: "sharedResponseSchema";
            readonly type: "object";
            readonly description: "";
            readonly "x-examples": {};
            readonly properties: {
                readonly reference_id: {
                    readonly type: "string";
                    readonly description: "A unique, randomly generated hex value that identifies your web service request.";
                    readonly minLength: 32;
                    readonly maxLength: 32;
                    readonly examples: readonly ["0123456789ABCDEF0123456789ABCDEF"];
                };
                readonly sub_resource: {
                    readonly type: "string";
                    readonly description: "The subresource in the URL accessed by this request.";
                    readonly examples: readonly ["sms"];
                };
                readonly errors: {
                    readonly type: "array";
                    readonly description: "Contains an object specifying each error that occurred. If no errors occurred, the array is empty.";
                    readonly items: {
                        readonly type: "object";
                        readonly title: "errorObject";
                        readonly description: "Contains properties related to an error that occurred during processing of the request.";
                        readonly properties: {
                            readonly code: {
                                readonly type: "integer";
                                readonly description: "A numeric code specifying which error occurred.";
                                readonly examples: readonly [-10001];
                            };
                            readonly description: {
                                readonly type: "string";
                                readonly description: "Text describing the error that occurred.";
                                readonly examples: readonly ["Invalid Request: PhoneNumber Parameter"];
                            };
                        };
                    };
                };
                readonly status: {
                    readonly type: "object";
                    readonly description: "Contains properties describing the preliminary delivery status of the SMS you sent.";
                    readonly required: readonly ["updated_on", "code", "description"];
                    readonly properties: {
                        readonly updated_on: {
                            readonly type: "string";
                            readonly description: "An RFC 3339 timestamp indicating when the delivery status was last updated. ";
                            readonly examples: readonly ["2020-08-27T17:28:49.559307Z"];
                        };
                        readonly code: {
                            readonly type: "integer";
                            readonly description: "A numeric code indicating the delivery status of the SMS.";
                            readonly examples: readonly [290];
                        };
                        readonly description: {
                            readonly type: "string";
                            readonly description: "Text describing the delivery status of the SMS.";
                            readonly examples: readonly ["Message in progress"];
                        };
                    };
                };
                readonly verify: {
                    readonly type: "object";
                    readonly description: "Contains properties related to the verification status.";
                    readonly properties: {
                        readonly code_state: {
                            readonly type: "string";
                            readonly description: "Indicates whether the verification code you provided in your request matches that sent by Telesign to the end-user. At this point in the verification process, the status is always `UNKNOWN`.\n\n`UNKNOWN`";
                            readonly enum: readonly ["UNKNOWN"];
                            readonly examples: readonly ["UNKNOWN"];
                        };
                        readonly code_entered: {
                            readonly type: "string";
                            readonly description: "Always set to an empty string. There is no code entered by the end user at this point in the verification process.";
                        };
                    };
                };
                readonly phone_type: {
                    readonly title: "ScorePhoneType";
                    readonly type: "object";
                    readonly description: "This object is only included if enabled by the [Telesign Customer Support Team](mailto:support@telesign.com).";
                    readonly properties: {
                        readonly code: {
                            readonly type: "string";
                            readonly description: "One of the [phone type codes](/enterprise/docs/codes-languages-and-time-zones#phone-type-codes).";
                            readonly examples: readonly ["2"];
                        };
                        readonly description: {
                            readonly type: "string";
                            readonly description: "Text describing the phone type.";
                            readonly examples: readonly ["MOBILE"];
                        };
                    };
                };
                readonly numbering: {
                    readonly title: "ScoreNumbering";
                    readonly type: "object";
                    readonly description: "Contains properties related to the numbering attributes of the specified phone number. This object is only included if enabled by the [Telesign Customer Support Team](mailto:support@telesign.com).";
                    readonly properties: {
                        readonly original: {
                            readonly type: "object";
                            readonly description: "Contains details about the original phone number included in the request.";
                            readonly properties: {
                                readonly phone_number: {
                                    readonly type: "string";
                                    readonly description: "The base phone number without the [country dialing code](/enterprise/docs/codes-languages-and-time-zones#country-codes-and-dialing-codes).";
                                    readonly examples: readonly ["7833012348"];
                                };
                                readonly complete_phone_number: {
                                    readonly type: "string";
                                    readonly description: "The base phone number prefixed with the [country dialing code](/enterprise/docs/codes-languages-and-time-zones#country-codes-and-dialing-codes).";
                                    readonly examples: readonly ["17833012348"];
                                };
                                readonly country_code: {
                                    readonly type: "string";
                                    readonly description: "The 1, 2, or 3-digit [country dialing code](/enterprise/docs/codes-languages-and-time-zones#country-codes-and-dialing-codes). For example, the country dialing code for both the U.S.A. and Canada is `1`, and the country dialing code for the United Kingdom is `44`.";
                                    readonly examples: readonly ["1"];
                                };
                            };
                        };
                        readonly cleansing: {
                            readonly type: "object";
                            readonly description: "Contains details about how the phone number was cleansed. Phone cleansing corrects common formatting issues in submitted phone numbers.";
                            readonly properties: {
                                readonly call: {
                                    readonly type: "object";
                                    readonly description: "Contains cleansing details for the phone number if it is enabled to receive voice calls.";
                                    readonly properties: {
                                        readonly cleansed_code: {
                                            readonly type: "integer";
                                            readonly description: "One of the [phone number cleansing codes](/enterprise/docs/codes-languages-and-time-zones#phone-number-cleansing-codes) specifying the cleansing operation performed on the phone number.";
                                            readonly examples: readonly [100];
                                        };
                                        readonly country_code: {
                                            readonly type: "string";
                                            readonly description: "The 1, 2, or 3-digit [country dialing code](/enterprise/docs/codes-languages-and-time-zones#country-codes-and-dialing-codes). For example, the country dialing code for both the U.S.A. and Canada is `1`, and the country dialing code for United Kingdom is `44`.";
                                            readonly examples: readonly ["1"];
                                        };
                                        readonly max_length: {
                                            readonly type: "integer";
                                            readonly description: "The maximum number of digits allowed for phone numbers with this country dialing code.";
                                            readonly examples: readonly [10];
                                        };
                                        readonly min_length: {
                                            readonly type: "integer";
                                            readonly description: "The minimum number of digits allowed for phone numbers with this country dialing code.";
                                            readonly examples: readonly [10];
                                        };
                                        readonly phone_number: {
                                            readonly type: "string";
                                            readonly description: "The base phone number without the [country dialing code](/enterprise/docs/codes-languages-and-time-zones#country-codes-and-dialing-codes).";
                                            readonly examples: readonly ["7833012348"];
                                        };
                                    };
                                };
                                readonly sms: {
                                    readonly type: "object";
                                    readonly description: "Contains cleansing details for the phone number if it is enabled to receive SMS.";
                                    readonly properties: {
                                        readonly cleansed_code: {
                                            readonly type: "integer";
                                            readonly description: "One of the [phone number cleansing codes](/enterprise/docs/codes-languages-and-time-zones#phone-number-cleansing-codes) specifying the cleansing operation performed on the phone number.";
                                            readonly examples: readonly [100];
                                        };
                                        readonly country_code: {
                                            readonly type: "string";
                                            readonly description: "The 1, 2, or 3-digit [country dialing code](/enterprise/docs/codes-languages-and-time-zones#country-codes-and-dialing-codes). For example, the country dialing code for both the U.S.A. and Canada is `1`, and the country dialing code for United Kingdom is `44`.";
                                            readonly examples: readonly ["1"];
                                        };
                                        readonly max_length: {
                                            readonly type: "integer";
                                            readonly description: "The maximum number of digits allowed for phone numbers with this country dialing code.";
                                            readonly examples: readonly [10];
                                        };
                                        readonly min_length: {
                                            readonly type: "integer";
                                            readonly description: "The minimum number of digits allowed for phone numbers with this country dialing code.";
                                            readonly examples: readonly [10];
                                        };
                                        readonly phone_number: {
                                            readonly type: "string";
                                            readonly description: "The base phone number without the [country dialing code](/enterprise/docs/codes-languages-and-time-zones#country-codes-and-dialing-codes).";
                                            readonly examples: readonly ["7833012348"];
                                        };
                                    };
                                };
                            };
                        };
                    };
                };
                readonly risk: {
                    readonly title: "ScoreRisk";
                    readonly type: "object";
                    readonly description: "Contains properties related to the risk score for the specified phone number. Only returned when this feature has been enabled by the [Telesign Customer Support Team](mailto:support@telesign.com).";
                    readonly properties: {
                        readonly level: {
                            readonly type: "string";
                            readonly description: "The severity of the risk. [Score Scales](/enterprise/docs/intelligence-get-started#score-scales) provides a table with risk levels.";
                            readonly examples: readonly ["low"];
                        };
                        readonly recommendation: {
                            readonly type: "string";
                            readonly description: "The action that Telesign recommends that you take based on the risk score.\n\n`allow` `flag` `block`";
                            readonly enum: readonly ["allow", "flag", "block"];
                            readonly examples: readonly ["allow"];
                        };
                        readonly score: {
                            readonly type: "integer";
                            readonly description: "The risk score for this phone number.";
                        };
                    };
                };
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
        readonly "400": {
            readonly title: "sharedResponseSchema";
            readonly type: "object";
            readonly description: "";
            readonly properties: {
                readonly reference_id: {
                    readonly type: "string";
                    readonly description: "A unique, randomly generated hex value that identifies your web service request.";
                    readonly minLength: 32;
                    readonly maxLength: 32;
                    readonly examples: readonly ["0123456789ABCDEF0123456789ABCDEF"];
                };
                readonly sub_resource: {
                    readonly type: "string";
                    readonly description: "The subresource in the URL accessed by this request.";
                    readonly examples: readonly ["sms"];
                };
                readonly errors: {
                    readonly type: "array";
                    readonly description: "Contains an object specifying each error that occurred. If no errors occurred, the array is empty.";
                    readonly items: {
                        readonly type: "object";
                        readonly title: "errorObject";
                        readonly description: "Contains properties related to an error that occurred during processing of the request.";
                        readonly properties: {
                            readonly code: {
                                readonly type: "integer";
                                readonly description: "A numeric code specifying which error occurred.";
                                readonly examples: readonly [-10001];
                            };
                            readonly description: {
                                readonly type: "string";
                                readonly description: "Text describing the error that occurred.";
                                readonly examples: readonly ["Invalid Request: PhoneNumber Parameter"];
                            };
                        };
                    };
                };
                readonly status: {
                    readonly type: "object";
                    readonly description: "Contains properties describing the preliminary delivery status of the SMS you sent.";
                    readonly required: readonly ["updated_on", "code", "description"];
                    readonly properties: {
                        readonly updated_on: {
                            readonly type: "string";
                            readonly description: "An RFC 3339 timestamp indicating when the delivery status was last updated. ";
                            readonly examples: readonly ["2020-08-27T17:28:49.559307Z"];
                        };
                        readonly code: {
                            readonly type: "integer";
                            readonly description: "A numeric code indicating the delivery status of the SMS.";
                            readonly examples: readonly [290];
                        };
                        readonly description: {
                            readonly type: "string";
                            readonly description: "Text describing the delivery status of the SMS.";
                            readonly examples: readonly ["Message in progress"];
                        };
                    };
                };
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
        readonly "401": {
            readonly title: "sharedResponseSchema";
            readonly type: "object";
            readonly description: "";
            readonly properties: {
                readonly reference_id: {
                    readonly type: "string";
                    readonly description: "A unique, randomly generated hex value that identifies your web service request.";
                    readonly minLength: 32;
                    readonly maxLength: 32;
                    readonly examples: readonly ["0123456789ABCDEF0123456789ABCDEF"];
                };
                readonly sub_resource: {
                    readonly type: "string";
                    readonly description: "The subresource in the URL accessed by this request.";
                    readonly examples: readonly ["sms"];
                };
                readonly errors: {
                    readonly type: "array";
                    readonly description: "Contains an object specifying each error that occurred. If no errors occurred, the array is empty.";
                    readonly items: {
                        readonly type: "object";
                        readonly title: "errorObject";
                        readonly description: "Contains properties related to an error that occurred during processing of the request.";
                        readonly properties: {
                            readonly code: {
                                readonly type: "integer";
                                readonly description: "A numeric code specifying which error occurred.";
                                readonly examples: readonly [-10001];
                            };
                            readonly description: {
                                readonly type: "string";
                                readonly description: "Text describing the error that occurred.";
                                readonly examples: readonly ["Invalid Request: PhoneNumber Parameter"];
                            };
                        };
                    };
                };
                readonly status: {
                    readonly type: "object";
                    readonly description: "Contains properties describing the preliminary delivery status of the SMS you sent.";
                    readonly required: readonly ["updated_on", "code", "description"];
                    readonly properties: {
                        readonly updated_on: {
                            readonly type: "string";
                            readonly description: "An RFC 3339 timestamp indicating when the delivery status was last updated. ";
                            readonly examples: readonly ["2020-08-27T17:28:49.559307Z"];
                        };
                        readonly code: {
                            readonly type: "integer";
                            readonly description: "A numeric code indicating the delivery status of the SMS.";
                            readonly examples: readonly [290];
                        };
                        readonly description: {
                            readonly type: "string";
                            readonly description: "Text describing the delivery status of the SMS.";
                            readonly examples: readonly ["Message in progress"];
                        };
                    };
                };
                readonly signature_string: {
                    readonly type: "string";
                    readonly description: "Returned when request signature is not valid. Signature from failed authorization requests - doesn’t contain all required data (like x-ts-auth-method), or it’s not ordered properly.";
                    readonly examples: readonly ["POST\\napplication/x-www-form-urlencoded\\n\\nx-ts-auth-method: HMAC-SHA256\\nx-ts-date:Tue, 31 Jan 2024 11:36:42 GMT\\nx-ts-nonce:ab$CDef/gh123+II4jk\\nphone_number=11234567890\\n/v1/verify/sms"];
                };
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
        readonly "429": {
            readonly title: "sharedResponseSchema";
            readonly type: "object";
            readonly description: "";
            readonly properties: {
                readonly reference_id: {
                    readonly type: "string";
                    readonly description: "A unique, randomly generated hex value that identifies your web service request.";
                    readonly minLength: 32;
                    readonly maxLength: 32;
                    readonly examples: readonly ["0123456789ABCDEF0123456789ABCDEF"];
                };
                readonly sub_resource: {
                    readonly type: "string";
                    readonly description: "The subresource in the URL accessed by this request.";
                    readonly examples: readonly ["sms"];
                };
                readonly errors: {
                    readonly type: "array";
                    readonly description: "Contains an object specifying each error that occurred. If no errors occurred, the array is empty.";
                    readonly items: {
                        readonly type: "object";
                        readonly title: "errorObject";
                        readonly description: "Contains properties related to an error that occurred during processing of the request.";
                        readonly properties: {
                            readonly code: {
                                readonly type: "integer";
                                readonly description: "A numeric code specifying which error occurred.";
                                readonly examples: readonly [-10001];
                            };
                            readonly description: {
                                readonly type: "string";
                                readonly description: "Text describing the error that occurred.";
                                readonly examples: readonly ["Invalid Request: PhoneNumber Parameter"];
                            };
                        };
                    };
                };
                readonly status: {
                    readonly type: "object";
                    readonly description: "Contains properties describing the preliminary delivery status of the SMS you sent.";
                    readonly required: readonly ["updated_on", "code", "description"];
                    readonly properties: {
                        readonly updated_on: {
                            readonly type: "string";
                            readonly description: "An RFC 3339 timestamp indicating when the delivery status was last updated. ";
                            readonly examples: readonly ["2020-08-27T17:28:49.559307Z"];
                        };
                        readonly code: {
                            readonly type: "integer";
                            readonly description: "A numeric code indicating the delivery status of the SMS.";
                            readonly examples: readonly [290];
                        };
                        readonly description: {
                            readonly type: "string";
                            readonly description: "Text describing the delivery status of the SMS.";
                            readonly examples: readonly ["Message in progress"];
                        };
                    };
                };
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
        readonly "500": {
            readonly title: "sharedResponseSchema";
            readonly type: "object";
            readonly description: "";
            readonly properties: {
                readonly reference_id: {
                    readonly type: "string";
                    readonly description: "A unique, randomly generated hex value that identifies your web service request.";
                    readonly minLength: 32;
                    readonly maxLength: 32;
                    readonly examples: readonly ["0123456789ABCDEF0123456789ABCDEF"];
                };
                readonly sub_resource: {
                    readonly type: "string";
                    readonly description: "The subresource in the URL accessed by this request.";
                    readonly examples: readonly ["sms"];
                };
                readonly errors: {
                    readonly type: "array";
                    readonly description: "Contains an object specifying each error that occurred. If no errors occurred, the array is empty.";
                    readonly items: {
                        readonly type: "object";
                        readonly title: "errorObject";
                        readonly description: "Contains properties related to an error that occurred during processing of the request.";
                        readonly properties: {
                            readonly code: {
                                readonly type: "integer";
                                readonly description: "A numeric code specifying which error occurred.";
                                readonly examples: readonly [-10001];
                            };
                            readonly description: {
                                readonly type: "string";
                                readonly description: "Text describing the error that occurred.";
                                readonly examples: readonly ["Invalid Request: PhoneNumber Parameter"];
                            };
                        };
                    };
                };
                readonly status: {
                    readonly type: "object";
                    readonly description: "Contains properties describing the preliminary delivery status of the SMS you sent.";
                    readonly required: readonly ["updated_on", "code", "description"];
                    readonly properties: {
                        readonly updated_on: {
                            readonly type: "string";
                            readonly description: "An RFC 3339 timestamp indicating when the delivery status was last updated. ";
                            readonly examples: readonly ["2020-08-27T17:28:49.559307Z"];
                        };
                        readonly code: {
                            readonly type: "integer";
                            readonly description: "A numeric code indicating the delivery status of the SMS.";
                            readonly examples: readonly [290];
                        };
                        readonly description: {
                            readonly type: "string";
                            readonly description: "Text describing the delivery status of the SMS.";
                            readonly examples: readonly ["Message in progress"];
                        };
                    };
                };
                readonly signature_string: {
                    readonly type: "string";
                    readonly description: "Returned when request signature is not valid. Signature from failed authorization requests - doesn’t contain all required data (like x-ts-auth-method), or it’s not ordered properly.";
                    readonly examples: readonly ["POST\\napplication/x-www-form-urlencoded\\n\\nx-ts-auth-method: HMAC-SHA256\\nx-ts-date:Tue, 31 Jan 2024 11:36:42 GMT\\nx-ts-nonce:ab$CDef/gh123+II4jk\\nphone_number=11234567890\\n/v1/verify/sms"];
                };
            };
            readonly $schema: "http://json-schema.org/draft-04/schema#";
        };
    };
};
export { GetSmsVerifyStatus, ReportSmsVerifyCompletion, SendSmsVerifyCode };

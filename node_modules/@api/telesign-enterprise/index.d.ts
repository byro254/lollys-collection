import type * as types from './types';
import type { ConfigOptions, FetchResponse } from 'api/dist/core';
import Oas from 'oas';
import APICore from 'api/dist/core';
declare class SDK {
    spec: Oas;
    core: APICore;
    constructor();
    /**
     * Optionally configure various options that the SDK allows.
     *
     * @param config Object of supported SDK options and toggles.
     * @param config.timeout Override the default `fetch` request timeout of 30 seconds. This number
     * should be represented in milliseconds.
     */
    config(config: ConfigOptions): void;
    /**
     * If the API you're using requires authentication you can supply the required credentials
     * through this method and the library will magically determine how they should be used
     * within your API request.
     *
     * With the exception of OpenID and MutualTLS, it supports all forms of authentication
     * supported by the OpenAPI specification.
     *
     * @example <caption>HTTP Basic auth</caption>
     * sdk.auth('username', 'password');
     *
     * @example <caption>Bearer tokens (HTTP or OAuth 2)</caption>
     * sdk.auth('myBearerToken');
     *
     * @example <caption>API Keys</caption>
     * sdk.auth('myApiKey');
     *
     * @see {@link https://spec.openapis.org/oas/v3.0.3#fixed-fields-22}
     * @see {@link https://spec.openapis.org/oas/v3.1.0#fixed-fields-22}
     * @param values Your auth credentials for the API; can specify up to two strings or numbers.
     */
    auth(...values: string[] | number[]): this;
    /**
     * If the API you're using offers alternate server URLs, and server variables, you can tell
     * the SDK which one to use with this method. To use it you can supply either one of the
     * server URLs that are contained within the OpenAPI definition (along with any server
     * variables), or you can pass it a fully qualified URL to use (that may or may not exist
     * within the OpenAPI definition).
     *
     * @example <caption>Server URL with server variables</caption>
     * sdk.server('https://{region}.api.example.com/{basePath}', {
     *   name: 'eu',
     *   basePath: 'v14',
     * });
     *
     * @example <caption>Fully qualified server URL</caption>
     * sdk.server('https://eu.api.example.com/v14');
     *
     * @param url Server URL
     * @param variables An object of variables to replace into the server URL.
     */
    server(url: string, variables?: {}): void;
    /**
     * Use this action to send an SMS with a verification code to a recipient phone number.
     *
     * ## General requirements
     * * **Authentication:** [Basic](/enterprise/docs/authentication#basic-authentication)
     * (easiest to implement) or
     * [Digest](/enterprise/docs/authentication#digest-authentication)
     * * **Encoding:** Accepts only **UTF-8 unicode** characters as inputs.
     * * **Accepts:** `application/x-www-form-urlencoded`
     * * **Responds with:** `application/json`
     * * **Required headers:** `Content-Type - application/x-www-form-urlencoded`
     * * **Rate limit:** [Default rate limits by
     * product](https://support.telesign.com/s/article/do-you-have-any-rate-limits)
     *
     * @summary Send SMS verification code
     * @throws FetchError<400, types.SendSmsVerifyCodeResponse400> **Bad request.** The request could not be understood by the server due to malformed
     * syntax. Code against the Telesign status or error codes from the `status.code` and
     * `errors.code` properties in the response payload, rather than the HTTP status code of
     * the response.
     *
     *
     * | Status code | Status description   | Error code | Description   |
     * |------------|--------------------------|------------|--------------------------|
     * | 500 | Transaction not attempted | -10001     | Invalid Request: {parameter name}
     * Parameter: {parameter value} |
     * | 500 | Transaction not attempted | -10001     | Invalid Request: Missing Parameter:
     * {parameter name} |
     * | 500 | Transaction not attempted | -10001     | Invalid Request: {parameter name}
     * Parameter                 |
     * | 500 | Transaction not attempted | -10001     | Not Allowed Host: IP/Hostname
     * Parameter: {host_ip_address}/{host_name} |
     * | 500 | Transaction not attempted | -40006     | Bad request              |
     * @throws FetchError<401, types.SendSmsVerifyCodeResponse401> **Unauthorized.** The request requires user authentication. Code against the Telesign
     * status or error codes from the `status.code` and `errors.code` properties in the
     * response payload, rather than the HTTP status code of the response.
     *
     * | Status code | Status description   | Error code | Description   |
     * |------------|--------------------------|------------|--------------------------|
     * | 500 | Transaction not attempted | -10009     | Invalid source IP address |
     * | 500 | Transaction not attempted | -10033     | {phone_number} has not been verified
     * for this trial account. |
     * | 501 | Not authorized            | -20002     | This product is not enabled for this
     * Customer ID.  |
     * | 501 | Not authorized            | -30000     | Invalid Customer ID. |
     * | 501 | Not authorized            | -30001     | Customer ID Account Suspended. |
     * | 501 | Not authorized            | -30004     | Missing required 'Authorization' header
     * |
     * | 501 | Not authorized            | -30005     | Required 'Authorization' header is not
     * in the correct format|
     * | 501 | Not authorized            | -30006     | Invalid Signature |
     * | 501 | Not authorized            | -30007     | Missing required 'Date' or 'x-ts-date'
     * header    |
     * | 500 | Transaction not attempted | -30008     | Invalid 'x-ts-auth-method' header.|
     * | 501 | Not authorized            | -30009     | 'Date' or 'x-ts-date' header is not
     * RFC822 compliant  |
     * | 501 | Not authorized            | -30010     | 'Date' or 'x-ts-date' header is not
     * within tolerable range |
     * | 501 | Not authorized            | -30011     | 'x-ts-nonce' header value is either too
     * long or too short |
     * | 501 | Not authorized            | -30012     | 'x-ts-nonce' header value has been used
     * recently |
     * | 501 | Not authorized            | -30015     | Invalid API Key.  |
     * @throws FetchError<429, types.SendSmsVerifyCodeResponse429> **Too many requests.** The user sent too many requests in a given amount of time. Code
     * against the Telesign status or error codes from the `status.code` and `errors.code`
     * properties in the response payload, rather than the HTTP status code of the response.
     *
     * | Status code | Status description   | Error code | Description   |
     * |------------|--------------------------|------------|--------------------------|
     * | 500 | Transaction not attempted | -40007     | Rate Limit Exceeded   |
     * | 500 | Transaction not attempted | -40008     | Verify SMS exceeded transaction hard
     * cap. Request denied.         |
     * @throws FetchError<500, types.SendSmsVerifyCodeResponse500> **Service unavailable.** The system is unavailable, try again. Code against the
     * Telesign status or error codes from the `status.code` and `errors.code` properties in
     * the response payload, rather than the HTTP status code of the response.
     *
     * | Status code | Status description   | Error code | Description   |
     * |------------|--------------------------|------------|--------------------------|
     * | 500 | Transaction not attempted | -90001  | System Unavailable, please try again
     * later.  |
     */
    sendSMSVerifyCode(body: types.SendSmsVerifyCodeFormDataParam): Promise<FetchResponse<200, types.SendSmsVerifyCodeResponse200>>;
    /**
     * Get delivery status and other details for a Telesign SMS Verify API transaction that you
     * have created. Use this endpoint also to complete verification, if Telesign generated
     * your code.
     *
     * ## General requirements
     * * **Authentication:** [Basic](/enterprise/docs/authentication#basic-authentication)
     * (easiest to implement) or
     * [Digest](/enterprise/docs/authentication#digest-authentication)
     * * **Encoding:** Accepts only **UTF-8 unicode** characters as inputs.
     * * **Accepts:** `application/x-www-form-urlencoded`
     * * **Required headers:** `Content-Type - application/x-www-form-urlencoded`
     * * **Rate limit:** [Default rate limits by
     * product](https://support.telesign.com/s/article/do-you-have-any-rate-limits)
     *
     * @summary Get transaction status
     * @throws FetchError<400, types.GetSmsVerifyStatusResponse400> Bad request. The request could not be understood by the server due to malformed syntax.
     * Code against the Telesign status or error codes from the `status.code` and `errors.code`
     * properties in the response payload, rather than the HTTP status code of the response.
     *
     * | Error Code | Associated text string   |
     * |------------|--------------------------|
     * | -10001     | Invalid Request: ReferenceID Parameter: <reference_id> |
     * | -10001     | Invalid Request: CustomerID Parameter: <customer_id>   |
     * | -10001     | Invalid Request: AuthenticationID                      |
     * | -10001     | Invalid Request: CustomerID/AuthenticationID Parameter:
     * <customer_id>/<authentication_id> |
     * | -10001     | Invalid Request: customer_id Parameter: <customer_id> |
     *
     * Associated text string for -10001 will change depending on the parameter.
     * @throws FetchError<401, types.GetSmsVerifyStatusResponse401> Unauthorized. The request requires user authentication. Code against the Telesign
     * status or error codes from the `status.code` and `errors.code` properties in the
     * response payload, rather than the HTTP status code of the response.
     *
     * | Error Code | Associated text string   |
     * |------------|--------------------------|
     * | -10001     | Not Allowed Host: Hostname Parameter: \<parameter> |
     * | -10001     | Not Allowed Host: IP Parameter: \<parameter> |
     * | -10009     | Invalid source IP address. |
     * | -20001     | Invalid Request: CustomerID Parameter: <customer_id> |
     * | -20002     | This product is not enabled for this Customer ID.  |
     * | -30000     | Invalid Customer ID.     |
     * | -30001     | Customer ID Account Suspended.                     |
     * | -30002     | Customer ID Account Not Activated.                 |
     * | -30003     | Customer ID new account limit reached.             |
     * | -30004     | Missing required 'Authorization' header |
     * | -30005     | Required 'Authorization' header is not in the correct format |
     * | -30006     | Invalid Signature |
     * | -30007     | Missing required 'Date' or 'x-ts-date' header    |
     * | -30008     | Invalid 'x-ts-auth-method' header. |
     * | -30009     | 'Date' or 'x-ts-date' header is not RFC822 compliant |
     * | -30010     | 'Date' or 'x-ts-date' header is not within tolerable range |
     * | -30011     | 'x-ts-nonce' header value is either too long or too short |
     * | -30012     | 'x-ts-nonce' header value has been used recently |
     * | -30015     | Invalid API Key. |
     *
     * @throws FetchError<404, types.GetSmsVerifyStatusResponse404> Not found. The server has not found anything matching the request URI. Code against the
     * Telesign status or error codes from the `status.code` and `errors.code` properties in
     * the response payload, rather than the HTTP status code of the response.
     *
     * | Error Code | Associated text string   |
     * |------------|--------------------------|
     * | -10001     | CustomerID/ReferenceID not found |
     * | -10001     | CustomerID/ReferenceID not found: CustomerID/ReferenceID Parameter:
     * \<parameter> |
     * | -10004     | Reference ID expired.     |
     *
     * Associated text string for -10001 will change depending on the parameter.
     * @throws FetchError<429, types.GetSmsVerifyStatusResponse429> Too many requests. The user sent too many requests in a given amount of time. Code
     * against the Telesign status or error codes from the `status.code` and `errors.code`
     * properties in the response payload, rather than the HTTP status code of the response.
     *
     * | Error Code | Associated text string   |
     * |------------|--------------------------|
     * | -40007     | Rate Limit Exceeded  |
     * | -40008     | \<product> exceeded transaction hard cap. Request denied.  |
     * @throws FetchError<503, types.GetSmsVerifyStatusResponse503> Service unavailable. The system is unavailable, try again. Code against the Telesign
     * status or error codes from the `status.code` and `errors.code` properties in the
     * response payload, rather than the HTTP status code of the response.
     *
     * | Error Code | Associated text string   |
     * |------------|--------------------------|
     * | -90001     | System Unavailable, please try again later.  |
     *
     */
    getSMSVerifyStatus(metadata: types.GetSmsVerifyStatusMetadataParam): Promise<FetchResponse<200, types.GetSmsVerifyStatusResponse200>>;
    /**
     * Use this action to notify Telesign that you have completed verification with the SMS
     * Verify API for an end-user. This is for a verification transaction where you generated
     * the verification code yourself.
     *
     * ## General requirements
     * * **Authentication:** [Basic](/enterprise/docs/authentication#basic-authentication)
     * (easiest to implement) or
     * [Digest](/enterprise/docs/authentication#digest-authentication)
     * * **Encoding:** Accepts only **UTF-8 unicode** characters as inputs.
     * * **Responds with:** `application/json`
     * * **Rate limit:** [Default rate limits by
     * product](https://support.telesign.com/s/article/do-you-have-any-rate-limits)
     *
     * @summary Report completion
     * @throws FetchError<400, types.ReportSmsVerifyCompletionResponse400> Bad request. The request could not be understood by the server due to malformed syntax.
     * Code against the Telesign status or error codes from the `status.code` and `errors.code`
     * properties in the response payload, rather than the HTTP status code of the response.
     *
     * | Status code | Associated text string |
     * |--|--|
     * | -10001 | Invalid parameter passed |
     *
     * @throws FetchError<401, types.ReportSmsVerifyCompletionResponse401> Unauthorized. The request requires user authentication. Code against the Telesign
     * status or error codes from the `status.code` and `errors.code` properties in the
     * response payload, rather than the HTTP status code of the response.
     *
     *  | Status code | Associated text string |
     *  |-------------|------------------------|
     *  | -30000 | Invalid customer ID |
     *  | -30001 | Account suspended |
     *  | -30002 | Account not activated |
     *  | -30003 | Account limit reached |
     *  | -30004 | Missing required Authorization header |
     *  | -30005 | Required Authorization header is not in the correct format |
     *  | -30006 | Invalid signature |
     *  | -30007 | Missing required Date or X-TS-Date header |
     *  | -30008 | Invalid X-TS-Auth-Method header |
     *  | -30009 | Date or X-TS-Date header is not [RFC822
     * compliant](https://www.w3.org/Protocols/rfc822/) |
     *  | -30010 | Date or X-TS-Date header is not within tolerable range |
     *  | -30011 | X-TS-Nonce header value is either too long or too short |
     *  | -30012 | X-TS-Nonce header value has been used recently |
     *  | -30013 | Invalid ReferenceID for Verify Completion |
     *
     *
     * @throws FetchError<404, types.ReportSmsVerifyCompletionResponse404> Not found. The server has not found anything matching the request URI. Code against the
     * Telesign status or error codes from the `status.code` and `errors.code` properties in
     * the response payload, rather than the HTTP status code of the response.
     *
     * | Status code | Associated text string |
     * |-------------|------------------------|
     * | -10001       | Customer ID / Reference ID not found           |
     *
     * @throws FetchError<503, types.ReportSmsVerifyCompletionResponse503> Service unavailable. The system is unavailable, try again. Code against the Telesign
     * status or error codes from the `status.code` and `errors.code` properties in the
     * response payload, rather than the HTTP status code of the response.
     *
     */
    reportSMSVerifyCompletion(metadata: types.ReportSmsVerifyCompletionMetadataParam): Promise<FetchResponse<200, types.ReportSmsVerifyCompletionResponse200>>;
}
declare const createSDK: SDK;
export = createSDK;

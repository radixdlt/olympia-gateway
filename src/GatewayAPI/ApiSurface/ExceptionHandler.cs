/* Copyright 2021 Radix Publishing Ltd incorporated in Jersey (Channel Islands).
 *
 * Licensed under the Radix License, Version 1.0 (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the License at:
 *
 * radixfoundation.org/licenses/LICENSE-v1
 *
 * The Licensor hereby grants permission for the Canonical version of the Work to be
 * published, distributed and used under or by reference to the Licensor’s trademark
 * Radix ® and use of any unregistered trade names, logos or get-up.
 *
 * The Licensor provides the Work (and each Contributor provides its Contributions) on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied,
 * including, without limitation, any warranties or conditions of TITLE, NON-INFRINGEMENT,
 * MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Whilst the Work is capable of being deployed, used and adopted (instantiated) to create
 * a distributed ledger it is your responsibility to test and validate the code, together
 * with all logic and performance of that code under all foreseeable scenarios.
 *
 * The Licensor does not make or purport to make and hereby excludes liability for all
 * and any representation, warranty or undertaking in any form whatsoever, whether express
 * or implied, to any entity or person, including any representation, warranty or
 * undertaking, as to the functionality security use, value or other characteristics of
 * any distributed ledger nor in respect the functioning or value of any tokens which may
 * be created stored or transferred using the Work. The Licensor does not warrant that the
 * Work or any use of the Work complies with any law or regulation in any territory where
 * it may be implemented or used or that it will be appropriate for any specific purpose.
 *
 * Neither the licensor nor any current or former employees, officers, directors, partners,
 * trustees, representatives, agents, advisors, contractors, or volunteers of the Licensor
 * shall be liable for any direct or indirect, special, incidental, consequential or other
 * losses of any kind, in tort, contract or otherwise (including but not limited to loss
 * of revenue, income or profits, or loss of use or data, or loss of reputation, or loss
 * of any economic or other opportunity of whatsoever nature or howsoever arising), arising
 * out of or in connection with (without limitation of any use, misuse, of any ledger system
 * or use made or its functionality or any performance or operation of any code or protocol
 * caused by bugs or programming or logic errors or otherwise);
 *
 * A. any offer, purchase, holding, use, sale, exchange or transmission of any
 * cryptographic keys, tokens or assets created, exchanged, stored or arising from any
 * interaction with the Work;
 *
 * B. any failure in a transmission or loss of any token or assets keys or other digital
 * artefacts due to errors in transmission;
 *
 * C. bugs, hacks, logic errors or faults in the Work or any communication;
 *
 * D. system software or apparatus including but not limited to losses caused by errors
 * in holding or transmitting tokens by any third-party;
 *
 * E. breaches or failure of security including hacker attacks, loss or disclosure of
 * password, loss of private key, unauthorised use or misuse of such passwords or keys;
 *
 * F. any losses including loss of anticipated savings or other benefits resulting from
 * use of the Work or any changes to the Work (however implemented).
 *
 * You are solely responsible for; testing, validating and evaluation of all operation
 * logic, functionality, security and appropriateness of using the Work for any commercial
 * or non-commercial purpose and for any reproduction or redistribution by You of the
 * Work. You assume all risks associated with Your use of the Work and the exercise of
 * permissions under this License.
 */

using Common.Exceptions;
using GatewayAPI.Exceptions;
using Microsoft.AspNetCore.Mvc;
using Core = RadixCoreApi.Generated.Model;
using CoreClient = RadixCoreApi.Generated.Client;
using Gateway = RadixGatewayApi.Generated.Model;

namespace GatewayAPI.ApiSurface;

public interface IExceptionHandler
{
    ActionResult CreateAndLogApiResultFromException(Exception exception, string traceId);
}

public class ExceptionHandler : IExceptionHandler
{
    private readonly ILogger<ExceptionHandler> _logger;
    private readonly LogLevel _knownGatewayErrorLogLevel;

    public ExceptionHandler(ILogger<ExceptionHandler> logger, IHostEnvironment env)
    {
        _logger = logger;
        _knownGatewayErrorLogLevel = env.IsDevelopment() ? LogLevel.Information : LogLevel.Debug;
    }

    public ActionResult CreateAndLogApiResultFromException(Exception exception, string traceId)
    {
        var gatewayErrorException = LogAndConvertToKnownGatewayErrorException(exception, traceId);

        return new JsonResult(new Gateway.ErrorResponse(
            code: gatewayErrorException.StatusCode,
            message: gatewayErrorException.UserFacingMessage,
            details: gatewayErrorException.GatewayError,
            traceId: traceId
        ))
        {
            StatusCode = 500,
        };
    }

    private KnownGatewayErrorException LogAndConvertToKnownGatewayErrorException(Exception exception, string traceId)
    {
        switch (exception)
        {
            case InvalidTransactionException invalidTransactionException:
                var mappedCoreApiException = ExtractKnownGatewayExceptionFromWrappedCoreApiExceptionOrNull(invalidTransactionException.WrappedCoreApiException);
                if (mappedCoreApiException != null)
                {
                    _logger.Log(
                        _knownGatewayErrorLogLevel,
                        mappedCoreApiException,
                        "Recognised / mapped exception from upstream core API [RequestTrace={TraceId}]",
                        traceId
                    );
                    return mappedCoreApiException;
                }

                _logger.Log(
                    _knownGatewayErrorLogLevel,
                    exception,
                    "General invalid transaction exception [RequestTrace={TraceId}]",
                    traceId
                );
                return invalidTransactionException;

            case KnownGatewayErrorException knownGatewayErrorException:
                _logger.Log(
                    _knownGatewayErrorLogLevel,
                    exception,
                    "Known exception with http response code [RequestTrace={TraceId}]",
                    traceId
                );
                return knownGatewayErrorException;

            // HttpRequestException is returned from the Core API if we can't connect
            case HttpRequestException:
                _logger.Log(
                    LogLevel.Information,
                    exception,
                    "Error relaying request to upstream server [RequestTrace={TraceId}]",
                    traceId
                );
                return InternalServerException.OfInvalidGatewayException(traceId);

            // WrappedCoreApiException is returned if we get a 500 from upstream and could parse out the error response
            case WrappedCoreApiException wrappedCoreApiException:
                var mappedException = ExtractKnownGatewayExceptionFromWrappedCoreApiExceptionOrNull(wrappedCoreApiException);

                if (mappedException != null)
                {
                    _logger.Log(
                        _knownGatewayErrorLogLevel,
                        mappedException,
                        "Returning mapped exception from upstream core API [RequestTrace={TraceId}]",
                        traceId
                    );
                    return mappedException;
                }

                _logger.Log(
                    LogLevel.Warning,
                    exception,
                    "Unhandled error response from upstream core API [RequestTrace={TraceId}]",
                    traceId
                );
                return InternalServerException.OfUnhandledCoreApiException(
                    wrappedCoreApiException.ApiException.ErrorContent.ToString() ?? string.Empty,
                    traceId
                );

            // CoreClient.ApiException is returned if we get a 500 from upstream but couldn't extract a WrappedCoreApiException
            case CoreClient.ApiException coreApiException:
                _logger.Log(
                    LogLevel.Warning,
                    exception,
                    "Unhandled error response from upstream core API, which didn't parse correctly into a known ErrorType we could wrap [RequestTrace={TraceId}]",
                    traceId
                );
                return InternalServerException.OfUnhandledCoreApiException(
                    coreApiException.ErrorContent.ToString() ?? string.Empty,
                    traceId
                );

            case InvalidCoreApiResponseException invalidCoreApiResponseException:
                _logger.Log(
                    LogLevel.Warning,
                    exception,
                    "Invalid Core API response [RequestTrace={TraceId}]",
                    traceId
                );
                return InternalServerException.OfInvalidCoreApiResponseException(
                    invalidCoreApiResponseException,
                    traceId
                );

            default:
                _logger.Log(
                    LogLevel.Warning,
                    exception,
                    "Unknown exception [RequestTrace={TraceId}]",
                    traceId
                );
                return InternalServerException.OfHiddenException(exception, traceId);
        }
    }

    private KnownGatewayErrorException? ExtractKnownGatewayExceptionFromWrappedCoreApiExceptionOrNull(WrappedCoreApiException? wrappedCoreApiException)
    {
        if (wrappedCoreApiException == null)
        {
            return null;
        }

        /*
         * Not all of the errors can be converted sensibly at this point. Errors fall into various categories:
         * 1) Client errors due to how the Gateway API has constructed a Core API request - these are Gateway API bugs
         *   and should be Gateway 500s
         * 2) Client errors which are errors of the Gateway API client - and which are specific enough to be passed
         *   through directly to the client - these are mapped below for ease
         * 3) Client errors which are errors of the Gateway API client - but which the errors at the Gateway API
         *   abstraction level are more detailed. These fall into two sub-categories:
         *   3a) Errors which should be noticed before sending the Core API request. So if we received a Core API error of
         *     this type, we should return a 500 (eg a Core.NotEnoughResourcesError which doesn't relate to fees - which
         *     we should have already mapped into a more specific type like Gateway.NotEnoughTokensForTransferError in
         *     the TransactionBuilder)
         *   3b) Errors which need to be remapped/re-interpreted by the Gateway service. EG extracting a
         *     Gateway.NotEnoughNativeTokensForFeeError from a Core.NotEnoughResourcesError or
         *     Core.NotEnoughNativeTokensForFeesError in the ConstructionAndSubmissionService
         *     If these errors propagate to this point, we should also return a 500.
         * 4) Core API Internal server errors - we return Gateway 500s for these.
         *
         * Essentially only errors of type (2) can and should be mapped below - the rest are unmapped and will return
         * as a 500.
         */
        return wrappedCoreApiException switch
        {
            WrappedCoreApiException<Core.AboveMaximumValidatorFeeIncreaseError> ex => InvalidRequestException.FromOtherError(
                $"You attempted to increase validator fee by {ex.Error.AttemptedValidatorFeeIncrease}, larger than the maximum of {ex.Error.MaximumValidatorFeeIncrease}"
            ),
            WrappedCoreApiException<Core.BelowMinimumStakeError> ex => new BelowMinimumStakeException(
                requestedAmount: ex.Error.MinimumStake.AsGatewayTokenAmount(),
                minimumAmount: ex.Error.MinimumStake.AsGatewayTokenAmount()
            ),
            WrappedCoreApiException<Core.FeeConstructionError> ex => new CouldNotConstructFeesException(ex.Error.Attempts),
            WrappedCoreApiException<Core.InvalidPublicKeyError> ex => new InvalidPublicKeyException(
                new Gateway.PublicKey(ex.Error.InvalidPublicKey.Hex),
                "Invalid public key"
            ),
            WrappedCoreApiException<Core.MessageTooLongError> ex => new MessageTooLongException(
                ex.Error.MaximumMessageLength,
                ex.Error.AttemptedMessageLength
            ),
            WrappedCoreApiException<Core.PublicKeyNotSupportedError> ex => new InvalidPublicKeyException(
                new Gateway.PublicKey(ex.Error.UnsupportedPublicKey.Hex),
                "Public key is not supported"
            ),
            WrappedCoreApiException<Core.TransactionNotFoundError> ex => new TransactionNotFoundException(
                new Gateway.TransactionIdentifier(ex.Error.TransactionIdentifier.Hash)
            ),
            _ => null,
        };
    }
}

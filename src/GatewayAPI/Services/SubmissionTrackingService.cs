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

using Common.CoreCommunications;
using Common.Database.Models.Mempool;
using Common.Extensions;
using GatewayAPI.Database;
using Microsoft.EntityFrameworkCore;
using NodaTime;
using Npgsql;
using Prometheus;
using Core = RadixCoreApi.Generated.Model;
using Gateway = RadixGatewayApi.Generated.Model;

namespace GatewayAPI.Services;

public interface ISubmissionTrackingService
{
    Task<MempoolTransaction?> GetMempoolTransaction(byte[] transactionIdentifierHash);

    Task<MempoolTrackGuidance> TrackInitialSubmission(
        byte[] signedTransaction,
        byte[] transactionIdentifierHash,
        string submittedToNodeName,
        Core.ConstructionParseResponse parseResponse
    );

    Task MarkAsFailed(
        byte[] transactionIdentifierHash,
        MempoolTransactionFailureReason failureReason,
        string failureExplanation
    );
}

public record MempoolTrackGuidance(bool ShouldSubmitToNode, MempoolTransactionFailureReason? TransactionAlreadyFailedReason = null);

public class SubmissionTrackingService : ISubmissionTrackingService
{
    private static readonly Counter _dbMempoolTransactionsAddedDueToSubmissionCount = Metrics
        .CreateCounter(
            "ng_db_mempool_transactions_added_from_gateway_submission_count",
            "Number of mempool transactions added to the DB due to being submitted to the gateway"
        );

    private readonly GatewayReadWriteDbContext _dbContext;
    private readonly IParsedTransactionMapper _parsedTransactionMapper;

    public SubmissionTrackingService(GatewayReadWriteDbContext dbContext, IParsedTransactionMapper parsedTransactionMapper)
    {
        _dbContext = dbContext;
        _parsedTransactionMapper = parsedTransactionMapper;
    }

    public async Task<MempoolTransaction?> GetMempoolTransaction(byte[] transactionIdentifierHash)
    {
        return await _dbContext.MempoolTransactions
            .Where(t => t.TransactionIdentifierHash == transactionIdentifierHash)
            .SingleOrDefaultAsync();
    }

    public async Task<MempoolTrackGuidance> TrackInitialSubmission(
        byte[] signedTransaction,
        byte[] transactionIdentifierHash,
        string submittedToNodeName,
        Core.ConstructionParseResponse parseResponse
    )
    {
        var submittedTimestamp = SystemClock.Instance.GetCurrentInstant();

        var existingMempoolTransaction = await GetMempoolTransaction(transactionIdentifierHash);

        if (existingMempoolTransaction != null)
        {
            if (existingMempoolTransaction.Status == MempoolTransactionStatus.Failed)
            {
                return new MempoolTrackGuidance(ShouldSubmitToNode: false, TransactionAlreadyFailedReason: existingMempoolTransaction.FailureReason);
            }

            existingMempoolTransaction.MarkAsSubmittedToGateway(submittedTimestamp);
            await _dbContext.SaveChangesAsync();

            // It's already been submitted to a node - this will be handled by the resubmission service if appropriate
            return new MempoolTrackGuidance(ShouldSubmitToNode: false);
        }

        var transactionContents = (await _parsedTransactionMapper.MapToGatewayTransactionContents(
            new List<Core.ConstructionParseResponse> { parseResponse }
        ))[0];

        var mempoolTransaction = MempoolTransaction.NewAsSubmittedForFirstTimeByGateway(
            transactionIdentifierHash,
            signedTransaction,
            submittedToNodeName,
            transactionContents,
            submittedTimestamp
        );

        _dbContext.MempoolTransactions.Add(mempoolTransaction);

        // We now try saving to the DB - but catch duplicates - if we get a duplicate reported, the gateway which saved
        // it successfully should then submit it to the node -- and the one that reports a duplicate should return a
        // generic success, but not resubmit.
        // NB - 23 is Integrity Constraint Violation: https://www.postgresql.org/docs/current/errcodes-appendix.html)
        try
        {
            await _dbContext.SaveChangesAsync();
            _dbMempoolTransactionsAddedDueToSubmissionCount.Inc();
            return new MempoolTrackGuidance(ShouldSubmitToNode: true);
        }
        catch (DbUpdateException ex) when ((ex.InnerException is PostgresException pg) && pg.SqlState.StartsWith("23"))
        {
            return new MempoolTrackGuidance(ShouldSubmitToNode: false);
        }
    }

    public async Task MarkAsFailed(
        byte[] transactionIdentifierHash,
        MempoolTransactionFailureReason failureReason,
        string failureExplanation
    )
    {
        var mempoolTransaction = await GetMempoolTransaction(transactionIdentifierHash);

        if (mempoolTransaction == null)
        {
            throw new Exception($"Could not find mempool transaction {transactionIdentifierHash.ToHex()} to mark it as failed");
        }

        mempoolTransaction.MarkAsFailed(failureReason, failureExplanation);

        await _dbContext.SaveChangesAsync();
    }
}

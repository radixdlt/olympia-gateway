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
using Common.Extensions;
using DataAggregator.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using NodaTime;
using RadixCoreApi.Generated.Model;

namespace DataAggregator.LedgerExtension;

public record CommittedTransactionData(
    CommittedTransaction CommittedTransaction,
    TransactionSummary TransactionSummary,
    byte[] TransactionContents
);

public record TransactionSummary(
    long StateVersion,
    long Epoch,
    long IndexInEpoch,
    long RoundInEpoch,
    bool IsOnlyRoundChange,
    bool IsStartOfEpoch,
    bool IsStartOfRound,
    byte[] TransactionIdentifierHash,
    byte[] TransactionAccumulator,
    Instant RoundTimestamp,
    Instant CreatedTimestamp,
    Instant NormalizedRoundTimestamp
);

public static class TransactionSummarisation
{
    public static async Task<TransactionSummary> GetSummaryOfTransactionOnTopOfLedger(AggregatorDbContext dbContext, CancellationToken token)
    {
        var lastTransaction = await dbContext.LedgerTransactions
            .AsNoTracking()
            .OrderByDescending(lt => lt.ResultantStateVersion)
            .FirstOrDefaultAsync(token);

        var lastOverview = lastTransaction == null ? null : new TransactionSummary(
            StateVersion: lastTransaction.ResultantStateVersion,
            Epoch: lastTransaction.Epoch,
            IndexInEpoch: lastTransaction.IndexInEpoch,
            RoundInEpoch: lastTransaction.RoundInEpoch,
            IsOnlyRoundChange: lastTransaction.IsOnlyRoundChange,
            IsStartOfEpoch: lastTransaction.IsStartOfEpoch,
            IsStartOfRound: lastTransaction.IsStartOfRound,
            TransactionIdentifierHash: lastTransaction.TransactionIdentifierHash,
            TransactionAccumulator: lastTransaction.TransactionAccumulator,
            RoundTimestamp: lastTransaction.RoundTimestamp,
            CreatedTimestamp: lastTransaction.CreatedTimestamp,
            NormalizedRoundTimestamp: lastTransaction.NormalizedRoundTimestamp
        );

        return lastOverview ?? PreGenesisTransactionSummary();
    }

    public static TransactionSummary GenerateSummary(TransactionSummary lastTransaction, CommittedTransaction transaction)
    {
        long? newEpoch = null;
        long? newRoundInEpoch = null;
        Instant? newRoundTimestamp = null;
        var isOnlyRoundChange = true;

        foreach (var operationGroup in transaction.OperationGroups)
        {
            foreach (var operation in operationGroup.Operations)
            {
                if (operation.IsNotRoundDataOrValidatorBftData())
                {
                    isOnlyRoundChange = false;
                }

                if (operation.IsCreateOf<EpochData>(out var epochData))
                {
                    newEpoch = epochData.Epoch;
                }

                if (operation.IsCreateOf<RoundData>(out var newRoundData))
                {
                    newRoundInEpoch = newRoundData.Round;

                    // NB - the first round of the ledger has Timestamp 0 for some reason. Let's ignore it and use the prev timestamp
                    if (newRoundData.Timestamp != 0)
                    {
                        newRoundTimestamp = Instant.FromUnixTimeMilliseconds(newRoundData.Timestamp);
                    }
                }
            }
        }

        /* NB:
           The Epoch Transition Transaction sort of fits between epochs, but it seems to fit slightly more naturally
           as the _first_ transaction of a new epoch, as creates the next EpochData, and the RoundData to 0.
        */

        var isStartOfEpoch = newEpoch != null;
        var isStartOfRound = newRoundInEpoch != null;

        var roundTimestamp = newRoundTimestamp ?? lastTransaction.RoundTimestamp;
        var createdTimestamp = SystemClock.Instance.GetCurrentInstant();
        var normalizedRoundTimestamp = // Clamp between lastTransaction.NormalizedTimestamp and createdTimestamp
            roundTimestamp < lastTransaction.NormalizedRoundTimestamp ? lastTransaction.NormalizedRoundTimestamp
            : roundTimestamp > createdTimestamp ? createdTimestamp
            : roundTimestamp;

        return new TransactionSummary(
            StateVersion: transaction.CommittedStateIdentifier.StateVersion,
            Epoch: newEpoch ?? lastTransaction.Epoch,
            IndexInEpoch: isStartOfEpoch ? 0 : lastTransaction.IndexInEpoch + 1,
            RoundInEpoch: newRoundInEpoch ?? lastTransaction.RoundInEpoch,
            IsOnlyRoundChange: isOnlyRoundChange,
            IsStartOfEpoch: isStartOfEpoch,
            IsStartOfRound: isStartOfRound,
            TransactionIdentifierHash: transaction.TransactionIdentifier.Hash.ConvertFromHex(),
            TransactionAccumulator: transaction.CommittedStateIdentifier.TransactionAccumulator.ConvertFromHex(),
            RoundTimestamp: roundTimestamp,
            CreatedTimestamp: createdTimestamp,
            NormalizedRoundTimestamp: normalizedRoundTimestamp
        );
    }

    public static TransactionSummary PreGenesisTransactionSummary()
    {
        // Nearly all of theses turn out to be unused!
        return new TransactionSummary(
            StateVersion: 0,
            Epoch: 0,
            IndexInEpoch: 0,
            RoundInEpoch: 0,
            IsOnlyRoundChange: false,
            IsStartOfEpoch: false,
            IsStartOfRound: false,
            TransactionIdentifierHash: Array.Empty<byte>(), // Unused
            TransactionAccumulator: new byte[32], // All 0s
            RoundTimestamp: Instant.FromUnixTimeSeconds(0),
            CreatedTimestamp: SystemClock.Instance.GetCurrentInstant(),
            NormalizedRoundTimestamp: Instant.FromUnixTimeSeconds(0)
        );
    }
}

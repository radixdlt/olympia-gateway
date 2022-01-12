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

using Common.Database;
using Common.Database.Models.Ledger.History;
using Common.Database.Models.Ledger.Substates;
using Common.Numerics;
using GatewayAPI.ApiSurface;
using GatewayAPI.Services;
using Microsoft.EntityFrameworkCore;
using Gateway = RadixGatewayApi.Generated.Model;

namespace GatewayAPI.Database;

public interface IAccountQuerier
{
    Task<Gateway.AccountBalances> GetAccountBalancesAtState(string accountAddress, Gateway.LedgerState ledgerState);

    Task<Gateway.AccountStakesResponse> GetStakePositionsAtState(string accountAddress, Gateway.LedgerState ledgerState);

    Task<Gateway.AccountUnstakesResponse> GetUnstakePositionsAtState(string accountAddress, Gateway.LedgerState ledgerState);

    Task<AccountQuerier.CombinedStakeSnapshot> GetStakeSnapshotAtState(
        ValidatedAccountAddress accountAddress,
        ValidatedValidatorAddress validatorAddress,
        Gateway.LedgerState ledgerState
    );

    Task<Dictionary<string, TokenAmount>> GetResourceBalancesByRri(string accountAddress, Gateway.LedgerState ledgerState);
}

public class AccountQuerier : IAccountQuerier
{
    private readonly GatewayReadOnlyDbContext _dbContext;
    private readonly INetworkConfigurationProvider _networkConfigurationProvider;

    public AccountQuerier(GatewayReadOnlyDbContext dbContext, INetworkConfigurationProvider networkConfigurationProvider)
    {
        _dbContext = dbContext;
        _networkConfigurationProvider = networkConfigurationProvider;
    }

    public async Task<Gateway.AccountBalances> GetAccountBalancesAtState(string accountAddress, Gateway.LedgerState ledgerState)
    {
        var account = await _dbContext.Account(accountAddress, ledgerState._Version).SingleOrDefaultAsync();

        if (account == null)
        {
            return new Gateway.AccountBalances(
                new Gateway.TokenAmount("0", _networkConfigurationProvider.GetXrdTokenIdentifier()),
                new List<Gateway.TokenAmount>()
            );
        }

        return new Gateway.AccountBalances(
            await GetAccountTotalStakeBalance(account.Id, ledgerState),
            await GetAccountResourceBalancesAtState(account.Id, ledgerState)
        );
    }

    public async Task<Gateway.AccountStakesResponse> GetStakePositionsAtState(string accountAddress, Gateway.LedgerState ledgerState)
    {
        var account = await _dbContext.Account(accountAddress, ledgerState._Version).SingleOrDefaultAsync();

        if (account == null)
        {
            return new Gateway.AccountStakesResponse(
                ledgerState,
                new List<Gateway.AccountStakeEntry>(),
                new List<Gateway.AccountStakeEntry>()
            );
        }

        var allStakes = await GetAccountValidatorCombinedStakeSnapshots(account.Id, ledgerState).ToListAsync();

        return new Gateway.AccountStakesResponse(
            ledgerState,
            MapValidatorStakes(
                allStakes.Select(x => new StakePosition(
                    x.ValidatorAddress,
                    x.AccountValidatorStakeSnapshot.TotalPreparedXrdStake
                ))
            ),
            MapValidatorStakes(
                allStakes.Select(x => new StakePosition(
                    x.ValidatorAddress,
                    x.ValidatorStakeSnapshot.EstimateXrdConversion(x.AccountValidatorStakeSnapshot.TotalStakeUnits)
                ))
            )
        );
    }

    public async Task<CombinedStakeSnapshot> GetStakeSnapshotAtState(
        ValidatedAccountAddress accountAddress,
        ValidatedValidatorAddress validatorAddress,
        Gateway.LedgerState ledgerState
    )
    {
        return await GetAccountValidatorCombinedStakeSnapshot(accountAddress.Address, validatorAddress.Address, ledgerState)
            ?? new CombinedStakeSnapshot(
                validatorAddress.Address,
                AccountValidatorStakeSnapshot.GetDefault(),
                ValidatorStakeSnapshot.GetDefault()
            );
    }

    public async Task<Gateway.AccountUnstakesResponse> GetUnstakePositionsAtState(string accountAddress, Gateway.LedgerState ledgerState)
    {
        var account = await _dbContext.Account(accountAddress, ledgerState._Version).SingleOrDefaultAsync();

        if (account == null)
        {
            return new Gateway.AccountUnstakesResponse(
                ledgerState,
                new List<Gateway.AccountUnstakeEntry>(),
                new List<Gateway.AccountUnstakeEntry>()
            );
        }

        var allStakes = await GetAccountValidatorCombinedStakeSnapshots(account.Id, ledgerState).ToListAsync();

        return new Gateway.AccountUnstakesResponse(
            ledgerState,
            MapValidatorUnstakes(
                allStakes.Select(x => new UnstakePosition(
                    x.ValidatorAddress,
                    x.ValidatorStakeSnapshot.EstimateXrdConversion(x.AccountValidatorStakeSnapshot.TotalPreparedUnStakeUnits),
                    501 // TODO:NG-57 - Fix Epochs Until Unlocked to be determined by engine configuration from Core API
                ))
            ),
            MapValidatorUnstakes(
                await GetExitingUnstakes(account.Id, ledgerState)
            )
        );
    }

    public async Task<Dictionary<string, TokenAmount>> GetResourceBalancesByRri(string accountAddress, Gateway.LedgerState ledgerState)
    {
        var account = await _dbContext.Account(accountAddress, ledgerState._Version).SingleOrDefaultAsync();

        if (account == null)
        {
            return new Dictionary<string, TokenAmount>();
        }

        return await _dbContext.AccountResourceBalanceHistoryForAccountIdAtVersion(account.Id, ledgerState._Version)
            .Include(arb => arb.Resource)
            .ToDictionaryAsync(x => x.Resource.ResourceIdentifier, x => x.BalanceEntry.Balance);
    }

    private async Task<List<Gateway.TokenAmount>> GetAccountResourceBalancesAtState(long accountId, Gateway.LedgerState ledgerState)
    {
        var balances = await _dbContext.AccountResourceBalanceHistoryForAccountIdAtVersion(accountId, ledgerState._Version)
            .Include(arb => arb.Resource)
            .ToListAsync();

        return balances
            .Where(x => x.BalanceEntry.Balance.IsPositive())
            .OrderByDescending(x => x.BalanceEntry.Balance)
            .Select(x => x.BalanceEntry.Balance.AsGatewayTokenAmount(x.Resource.ResourceIdentifier))
            .ToList();
    }

    private async Task<Gateway.TokenAmount> GetAccountTotalStakeBalance(long accountId, Gateway.LedgerState ledgerState)
    {
        var allStakes = await GetAccountValidatorCombinedStakeSnapshots(accountId, ledgerState).ToListAsync();
        var totalXrd = TokenAmount.Zero;

        foreach (var s in allStakes)
        {
            var accountValidatorStakeSnapshot = s.AccountValidatorStakeSnapshot;
            var validatorStakeSnapshot = s.ValidatorStakeSnapshot;

            var definiteXrd = accountValidatorStakeSnapshot.TotalPreparedXrdStake
                              + accountValidatorStakeSnapshot.TotalExitingXrdStake;
            var stakeUnits = accountValidatorStakeSnapshot.TotalStakeUnits
                                 + accountValidatorStakeSnapshot.TotalPreparedUnStakeUnits;

            totalXrd += definiteXrd + validatorStakeSnapshot.EstimateXrdConversion(stakeUnits);
        }

        return totalXrd.AsGatewayTokenAmount(_networkConfigurationProvider.GetXrdTokenIdentifier());
    }

    private record StakePosition(string ValidatorAddress, TokenAmount Xrd);

    private List<Gateway.AccountStakeEntry> MapValidatorStakes(IEnumerable<StakePosition> stakes)
    {
        return stakes
            .Where(s => s.Xrd.IsPositive())
            .OrderByDescending(s => s.Xrd)
            .Select(s => new Gateway.AccountStakeEntry(
                s.ValidatorAddress.AsGatewayValidatorIdentifier(),
                s.Xrd.AsGatewayTokenAmount(_networkConfigurationProvider.GetXrdTokenIdentifier())
            ))
            .ToList();
    }

    private record UnstakePosition(string ValidatorAddress, TokenAmount Xrd, long EpochsUntilUnlocked);

    private List<Gateway.AccountUnstakeEntry> MapValidatorUnstakes(IEnumerable<UnstakePosition> stakes)
    {
        return stakes
            .Where(s => s.Xrd.IsPositive())
            .OrderByDescending(s => s.Xrd)
            .Select(s => new Gateway.AccountUnstakeEntry(
                s.ValidatorAddress.AsGatewayValidatorIdentifier(),
                s.Xrd.AsGatewayTokenAmount(_networkConfigurationProvider.GetXrdTokenIdentifier()),
                s.EpochsUntilUnlocked
            ))
            .ToList();
    }

    private async Task<IEnumerable<UnstakePosition>> GetExitingUnstakes(long accountId, Gateway.LedgerState ledgerState)
    {
        var stateVersion = ledgerState._Version;

        var exitingUnstakes = await (
            from exitingStakeSubstates in _dbContext.AccountXrdStakeBalanceSubstates.UpAtVersion(stateVersion)
            join validator in _dbContext.Validators
                on exitingStakeSubstates.ValidatorId equals validator.Id
            where
                exitingStakeSubstates.AccountId == accountId &&
                exitingStakeSubstates.Type == AccountXrdStakeBalanceSubstateType.ExitingStake
            select new { ValidatorAddress = validator.Address, XrdAmount = exitingStakeSubstates.Amount, UnlockEpoch = exitingStakeSubstates.UnlockEpoch }
        ).ToListAsync();

        return exitingUnstakes
            .GroupBy(s => (s.ValidatorAddress, s.UnlockEpoch))
            .Select(g =>
            {
                var (validatorAddress, unlockEpoch) = g.Key;
                return new UnstakePosition(
                    validatorAddress,
                    g.Select(s => s.XrdAmount).Aggregate((a, b) => a + b),
                    unlockEpoch.HasValue ? unlockEpoch.Value - ledgerState.Epoch : 0 // Shouldn't ever be null, but protect just in case
                );
            });
    }

    public record CombinedStakeSnapshot(
        string ValidatorAddress,
        AccountValidatorStakeSnapshot AccountValidatorStakeSnapshot,
        ValidatorStakeSnapshot ValidatorStakeSnapshot
    );

    private IQueryable<CombinedStakeSnapshot> GetAccountValidatorCombinedStakeSnapshots(long accountId, Gateway.LedgerState ledgerState)
    {
        var stateVersion = ledgerState._Version;

        return
            from stakeHistory in _dbContext.AccountValidatorStakeHistoryForAccountIdAtVersion(accountId, stateVersion)
            join validatorHistory in _dbContext.ValidatorStakeHistoryAtVersionForAnyValidator(stateVersion)
                on stakeHistory.ValidatorId equals validatorHistory.ValidatorId
            join validator in _dbContext.Validators
                on stakeHistory.ValidatorId equals validator.Id
            select new CombinedStakeSnapshot(validator.Address, stakeHistory.StakeSnapshot, validatorHistory.StakeSnapshot)
        ;
    }

    private async Task<CombinedStakeSnapshot?> GetAccountValidatorCombinedStakeSnapshot(string accountAddress, string validatorAddress, Gateway.LedgerState ledgerState)
    {
        var stateVersion = ledgerState._Version;

        var accountId = await _dbContext.Account(accountAddress, ledgerState._Version).Select(a => a.Id).SingleOrDefaultAsync();
        var validatorId = await _dbContext.Validator(validatorAddress, ledgerState._Version).Select(v => v.Id).SingleOrDefaultAsync();

        return await (
            from stakeHistory in _dbContext.AccountValidatorStakeHistoryForAccountIdAtVersion(accountId, stateVersion)
            join validatorHistory in _dbContext.ValidatorStakeHistoryAtVersionForValidatorId(validatorId, stateVersion)
                on stakeHistory.ValidatorId equals validatorHistory.ValidatorId
            join validator in _dbContext.Validators
                on stakeHistory.ValidatorId equals validator.Id
            select new CombinedStakeSnapshot(validator.Address, stakeHistory.StakeSnapshot, validatorHistory.StakeSnapshot)
        ).SingleOrDefaultAsync();
    }
}

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

using Common.Database.Models;
using Common.Database.Models.Ledger;
using Common.Database.Models.Ledger.History;
using Common.Database.Models.Ledger.Joins;
using Common.Database.Models.Ledger.Normalization;
using Common.Database.Models.Ledger.Records;
using Common.Database.Models.Ledger.Substates;
using Common.Database.Models.Mempool;
using Common.Database.Models.SingleEntries;
using Common.Database.ValueConverters;
using Common.Extensions;
using Common.Numerics;
using Microsoft.EntityFrameworkCore;

namespace Common.Database;

/// <summary>
/// Common DB Context for the Network Gateway database.
/// </summary>
public class CommonDbContext : DbContext
{
    public DbSet<Node> Nodes => Set<Node>();

    public DbSet<NetworkConfiguration> NetworkConfiguration => Set<NetworkConfiguration>();

    public DbSet<RawTransaction> RawTransactions => Set<RawTransaction>();

    public DbSet<LedgerStatus> LedgerStatus => Set<LedgerStatus>();

    public DbSet<LedgerTransaction> LedgerTransactions => Set<LedgerTransaction>();

    public DbSet<LedgerOperationGroup> OperationGroups => Set<LedgerOperationGroup>();

    public DbSet<AccountResourceBalanceSubstate> AccountResourceBalanceSubstates => Set<AccountResourceBalanceSubstate>();

    public DbSet<AccountXrdStakeBalanceSubstate> AccountXrdStakeBalanceSubstates => Set<AccountXrdStakeBalanceSubstate>();

    public DbSet<AccountStakeUnitBalanceSubstate> AccountStakeUnitBalanceSubstates => Set<AccountStakeUnitBalanceSubstate>();

    public DbSet<ValidatorStakeBalanceSubstate> ValidatorStakeBalanceSubstates => Set<ValidatorStakeBalanceSubstate>();

    public DbSet<ResourceDataSubstate> ResourceDataSubstates => Set<ResourceDataSubstate>();

    public DbSet<ValidatorDataSubstate> ValidatorDataSubstates => Set<ValidatorDataSubstate>();

    public DbSet<AccountResourceBalanceHistory> AccountResourceBalanceHistoryEntries => Set<AccountResourceBalanceHistory>();

    public DbSet<ResourceSupplyHistory> ResourceSupplyHistoryEntries => Set<ResourceSupplyHistory>();

    public DbSet<ValidatorStakeHistory> ValidatorStakeHistoryEntries => Set<ValidatorStakeHistory>();

    public DbSet<AccountValidatorStakeHistory> AccountValidatorStakeHistoryEntries => Set<AccountValidatorStakeHistory>();

    public DbSet<ValidatorProposalRecord> ValidatorProposalRecords => Set<ValidatorProposalRecord>();

    public DbSet<Account> Accounts => Set<Account>();

    public DbSet<Resource> Resources => Set<Resource>();

    public DbSet<Validator> Validators => Set<Validator>();

    public DbSet<AccountTransaction> AccountTransactions => Set<AccountTransaction>();

    public DbSet<MempoolTransaction> MempoolTransactions => Set<MempoolTransaction>();

    public CommonDbContext(DbContextOptions options)
        : base(options)
    {
    }

    // Note that PostGres doesn't have clustered indexes: all indexes are non-clustered, and operate against the heap
    // So secondary indexes might benefit from the inclusion of columns for faster lookups
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        HookupSingleEntries(modelBuilder);
        HookupTransactions(modelBuilder);
        HookupMempoolTransactions(modelBuilder);
        HookupLedgerOperationGroups(modelBuilder);
        HookupNormalizedEntities(modelBuilder);
        HookupSubstates(modelBuilder);
        HookupHistory(modelBuilder);
        HookupRecords(modelBuilder);
        HookupJoinTables(modelBuilder);
    }

    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        configurationBuilder.Properties<TokenAmount>()
            .HaveConversion<TokenAmountToBigIntegerConverter>()
            .HaveColumnType("numeric")
            .HavePrecision(1000, 0);

        configurationBuilder.Properties<InferredActionType>()
            .HaveConversion<InferredActionTypeValueConverter>();

        configurationBuilder.Properties<AccountStakeUnitBalanceSubstateType>()
            .HaveConversion<AccountStakeUnitBalanceSubstateTypeValueConverter>();

        configurationBuilder.Properties<AccountXrdStakeBalanceSubstateType>()
            .HaveConversion<AccountXrdStakeBalanceSubstateTypeValueConverter>();

        configurationBuilder.Properties<ResourceDataSubstateType>()
            .HaveConversion<ResourceDataSubstateTypeValueConverter>();

        configurationBuilder.Properties<ValidatorDataSubstateType>()
            .HaveConversion<ValidatorDataSubstateTypeValueConverter>();

        configurationBuilder.Properties<MempoolTransactionStatus>()
            .HaveConversion<MempoolTransactionStatusValueConverter>();

        configurationBuilder.Properties<MempoolTransactionFailureReason>()
            .HaveConversion<MempoolTransactionFailureReasonValueConverter>();
    }

    private static void HookupSingleEntries(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<LedgerStatus>()
            .HasOne(ls => ls.TopOfLedgerTransaction)
            .WithMany()
            .HasForeignKey(ls => ls.TopOfLedgerStateVersion)
            .HasConstraintName("FK_ledger_status_top_transactions_state_version")
            .OnDelete(DeleteBehavior.NoAction); // Should handle this manually
    }

    private static void HookupTransactions(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<LedgerTransaction>()
            .HasAlternateKey(lt => lt.TransactionIdentifierHash);

        modelBuilder.Entity<LedgerTransaction>()
            .HasAlternateKey(lt => lt.TransactionAccumulator);

        // Because NormalizedTimestamp and (Epoch, EndOfEpochRound) are correlated with the linear history of the table,
        // we could consider defining them as a BRIN index, using .HasMethod("brin")
        // This is a lighter (lossy) index where the indexed data is correlated with the linear order of the table
        // See also https://www.postgresql.org/docs/current/indexes-types.html

        // This index lets you quickly translate Time => StateVersion
        modelBuilder.Entity<LedgerTransaction>()
            .HasIndex(lt => lt.RoundTimestamp);

        // This index lets you quickly translate Epoch/Round => StateVersion
        modelBuilder.Entity<LedgerTransaction>()
            .HasIndex(lt => new { lt.Epoch, lt.RoundInEpoch })
            .IsUnique()
            .HasFilter("is_start_of_round = true");

        // This index allows us to use the LedgerTransactions as an Epoch table, to look up the start of each epoch
        modelBuilder.Entity<LedgerTransaction>()
            .HasIndex(lt => new { lt.Epoch })
            .IsUnique()
            .HasFilter("is_start_of_epoch = true");
    }

    private static void HookupMempoolTransactions(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<MempoolTransaction>()
            .HasIndex(lt => lt.Status);
    }

    private static void HookupLedgerOperationGroups(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<LedgerOperationGroup>()
            .HasKey(og => new { og.ResultantStateVersion, og.OperationGroupIndex });
    }

    private static void HookupNormalizedEntities(ModelBuilder modelBuilder)
    {
        HookupNormalizedEntity<Resource>(modelBuilder);
        modelBuilder.Entity<Resource>()
            .HasIndex(r => r.ResourceIdentifier)
            .IncludeProperties(r => r.Id)
            .IsUnique();

        HookupNormalizedEntity<Account>(modelBuilder);
        modelBuilder.Entity<Account>()
            .HasIndex(r => r.Address)
            .IncludeProperties(r => r.Id)
            .IsUnique();

        HookupNormalizedEntity<Validator>(modelBuilder);
        modelBuilder.Entity<Validator>()
            .HasIndex(r => r.Address)
            .IncludeProperties(r => r.Id)
            .IsUnique();
    }

    private static void HookupSubstates(ModelBuilder modelBuilder)
    {
        // Balance substates
        HookUpSubstate<AccountResourceBalanceSubstate>(modelBuilder);
        modelBuilder.Entity<AccountResourceBalanceSubstate>()
            .HasIndex(s => new { s.AccountId, s.ResourceId, s.Amount })
            .IncludeProperties(s => new { s.SubstateIdentifier })
            .HasFilter("down_state_version is null")
            .HasDatabaseName($"IX_{nameof(AccountResourceBalanceSubstate).ToSnakeCase()}_current_unspent_utxos");

        HookUpSubstate<AccountXrdStakeBalanceSubstate>(modelBuilder);
        HookUpSubstate<AccountStakeUnitBalanceSubstate>(modelBuilder);
        HookUpSubstate<ValidatorStakeBalanceSubstate>(modelBuilder);

        // Data substates
        HookUpSubstate<ResourceDataSubstate>(modelBuilder);
        HookUpSubstate<ValidatorDataSubstate>(modelBuilder);
    }

    private static void HookupHistory(ModelBuilder modelBuilder)
    {
        HookUpAccountResourceBalanceHistory(modelBuilder);
        HookUpResourceSupplyHistory(modelBuilder);
        HookUpValidatorStakeHistory(modelBuilder);
        HookUpAccountValidatorStakeHistory(modelBuilder);
    }

    private static void HookupRecords(ModelBuilder modelBuilder)
    {
        HookUpValidatorProposalRecords(modelBuilder);
    }

    private static void HookupJoinTables(ModelBuilder modelBuilder)
    {
        HookUpAccountTransactionJoinTable(modelBuilder);
    }

    private static void HookUpAccountResourceBalanceHistory(ModelBuilder modelBuilder)
    {
        HookupHistory<AccountResourceBalanceHistory>(modelBuilder);

        modelBuilder.Entity<AccountResourceBalanceHistory>()
            .HasKey(h => new { h.AccountId, h.ResourceId, h.FromStateVersion });

        modelBuilder.Entity<AccountResourceBalanceHistory>()
            .HasIndex(h => new { h.AccountId, h.ResourceId })
            .HasFilter("to_state_version is null")
            .IsUnique()
            .HasDatabaseName($"IX_{nameof(AccountResourceBalanceHistory).ToSnakeCase()}_current_balance");

        modelBuilder.Entity<AccountResourceBalanceHistory>()
            .HasIndex(h => new { h.AccountId, h.FromStateVersion });
        modelBuilder.Entity<AccountResourceBalanceHistory>()
            .HasIndex(h => new { h.ResourceId, h.AccountId, h.FromStateVersion });
        modelBuilder.Entity<AccountResourceBalanceHistory>()
            .HasIndex(h => new { h.ResourceId, h.FromStateVersion });
    }

    private static void HookUpResourceSupplyHistory(ModelBuilder modelBuilder)
    {
        HookupHistory<ResourceSupplyHistory>(modelBuilder);

        modelBuilder.Entity<ResourceSupplyHistory>()
            .HasKey(h => new { h.ResourceId, h.FromStateVersion });

        modelBuilder.Entity<ResourceSupplyHistory>()
            .HasIndex(h => new { h.ResourceId })
            .HasFilter("to_state_version is null")
            .IsUnique()
            .HasDatabaseName($"IX_{nameof(ResourceSupplyHistory).ToSnakeCase()}_current_supply");
    }

    private static void HookUpValidatorStakeHistory(ModelBuilder modelBuilder)
    {
        HookupHistory<ValidatorStakeHistory>(modelBuilder);

        modelBuilder.Entity<ValidatorStakeHistory>()
            .HasKey(h => new { h.ValidatorId, h.FromStateVersion });

        modelBuilder.Entity<ValidatorStakeHistory>()
            .HasIndex(h => new { h.ValidatorId })
            .HasFilter("to_state_version is null")
            .IsUnique()
            .HasDatabaseName($"IX_{nameof(ValidatorStakeHistory).ToSnakeCase()}_current_stake");
    }

    private static void HookUpAccountValidatorStakeHistory(ModelBuilder modelBuilder)
    {
        HookupHistory<AccountValidatorStakeHistory>(modelBuilder);

        modelBuilder.Entity<AccountValidatorStakeHistory>()
            .HasKey(h => new { h.AccountId, h.ValidatorId, h.FromStateVersion });

        modelBuilder.Entity<AccountValidatorStakeHistory>()
            .HasIndex(h => new { h.AccountId, h.ValidatorId })
            .HasFilter("to_state_version is null")
            .IsUnique()
            .HasDatabaseName($"IX_{nameof(AccountValidatorStakeHistory).ToSnakeCase()}_current_stake");

        modelBuilder.Entity<AccountValidatorStakeHistory>()
            .HasIndex(h => new { h.AccountId, h.FromStateVersion });
        modelBuilder.Entity<AccountValidatorStakeHistory>()
            .HasIndex(h => new { h.ValidatorId, h.AccountId, h.FromStateVersion });
        modelBuilder.Entity<AccountValidatorStakeHistory>()
            .HasIndex(h => new { h.ValidatorId, h.FromStateVersion });
    }

    private static void HookUpValidatorProposalRecords(ModelBuilder modelBuilder)
    {
        HookupRecord<ValidatorProposalRecord>(modelBuilder);

        modelBuilder.Entity<ValidatorProposalRecord>()
            .HasKey(h => new { h.Epoch, h.ValidatorId });

        modelBuilder.Entity<ValidatorProposalRecord>()
            .HasIndex(h => new { h.ValidatorId, h.Epoch });
    }

    private static void HookUpAccountTransactionJoinTable(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<AccountTransaction>()
            .HasKey(at => new { at.AccountId, at.ResultantStateVersion });
    }

    private static void HookUpSubstate<TSubstate>(ModelBuilder modelBuilder)
        where TSubstate : SubstateBase
    {
        var substateNameSnakeCase = typeof(TSubstate).Name.ToSnakeCase();

        modelBuilder.Entity<TSubstate>()
            .HasKey(s => new { s.UpStateVersion, s.UpOperationGroupIndex, s.UpOperationIndexInGroup });

        modelBuilder.Entity<TSubstate>()
            .HasAlternateKey(s => s.SubstateIdentifier);

        modelBuilder.Entity<TSubstate>()
            .HasOne(s => s.UpOperationGroup)
            .WithMany()
            .HasForeignKey(s => new
            {
                ResultantStateVersion = s.UpStateVersion,
                OperationGroupIndex = s.UpOperationGroupIndex,
            })
            .OnDelete(DeleteBehavior.Cascade) // Deletes Substate if OperationGroup deleted
            .HasConstraintName($"FK_{substateNameSnakeCase}_up_operation_group");

        modelBuilder.Entity<TSubstate>()
            .HasOne(s => s.DownOperationGroup)
            .WithMany()
            .HasForeignKey(s => new
            {
                ResultantStateVersion = s.DownStateVersion,
                OperationGroupIndex = s.DownOperationGroupIndex,
            })
            .OnDelete(DeleteBehavior.Restrict) // Null out FKs if OperationGroup deleted (all such dependents need to be loaded by EF Core at the time of deletion!)
            .HasConstraintName($"FK_{substateNameSnakeCase}_down_operation_group");
    }

    private static void HookupHistory<THistory>(ModelBuilder modelBuilder)
        where THistory : HistoryBase
    {
        var substateNameSnakeCase = typeof(THistory).Name.ToSnakeCase();

        modelBuilder.Entity<THistory>()
            .HasOne(h => h.FromLedgerTransaction)
            .WithMany()
            .HasForeignKey(h => h.FromStateVersion)
            .OnDelete(DeleteBehavior.Cascade) // Deletes History if LedgerTransaction deleted
            .HasConstraintName($"FK_{substateNameSnakeCase}_from_transaction");

        // Note - if the Ledger is rolled back then ToStateVersions need to be manually nulled out where
        //  ToStateVersion >= (FirstRevertedStateVersion - 1) to ensure we have the tip of the history with null
        //  ToStateVersion.
        modelBuilder.Entity<THistory>()
            .HasOne(h => h.ToLedgerTransaction)
            .WithMany()
            .HasForeignKey(h => h.ToStateVersion)
            .OnDelete(DeleteBehavior.Restrict) // Null out FKs if LedgerTransaction deleted (all such dependents need to be loaded by EF Core at the time of deletion!)
            .HasConstraintName($"FK_{substateNameSnakeCase}_to_transaction");
    }

    private static void HookupRecord<TRecord>(ModelBuilder modelBuilder)
        where TRecord : RecordBase
    {
        var substateNameSnakeCase = typeof(TRecord).Name.ToSnakeCase();

        modelBuilder.Entity<TRecord>()
            .HasOne(h => h.LastUpdatedAtLedgerTransaction)
            .WithMany()
            .HasForeignKey(h => h.LastUpdatedAtStateVersion)
            .OnDelete(DeleteBehavior.NoAction) // Reversions need to be handled manually for records in general
            .HasConstraintName($"FK_{substateNameSnakeCase}_last_updated_transaction");
    }

    private static void HookupNormalizedEntity<TNormalizedEntity>(ModelBuilder modelBuilder)
        where TNormalizedEntity : NormalizedEntityBase
    {
        var substateNameSnakeCase = typeof(TNormalizedEntity).Name.ToSnakeCase();

        modelBuilder.Entity<TNormalizedEntity>()
            .HasOne(ne => ne.FromLedgerTransaction)
            .WithMany()
            .HasForeignKey(ne => ne.FromStateVersion)
            .OnDelete(DeleteBehavior.Cascade) // Deletes if ledger is rolled back
            .HasConstraintName($"FK_{substateNameSnakeCase}_from_transaction");
    }
}

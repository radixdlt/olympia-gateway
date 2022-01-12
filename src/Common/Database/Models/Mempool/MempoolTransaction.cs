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

using Common.Database.ValueConverters;
using Newtonsoft.Json;
using NodaTime;
using NodaTime.Serialization.JsonNet;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Runtime.Serialization;
using Gateway = RadixGatewayApi.Generated.Model;

namespace Common.Database.Models.Mempool;

public enum MempoolTransactionStatus
{
    InNodeMempool, // We believe the transaction is in at least one node mempool, or has possibly (just) entered one
    Missing,       // A transaction which was previously InNodeMempool, but at last check, was no longer seen in any mempool
                   // after transitioning to Missing, we wait for a further delay before attempting resubmission, to allow the
                   // Gateway DB time to sync and mark it committed
    ResolvedButUnknownTillSyncedUp, // A transaction has been marked as substate not found by a node at resubmission, but we've yet to see it on ledger
                                    // because the aggregator service is not sufficiently synced up - so we don't know if it's been committed
                                    // and detected itself, or clashed with another transaction.
    Failed,        // A transaction which we have tried to (re)submit, but it returns a permanent error from the node (eg substate clash)
    Committed,     // A transaction which we know got committed to the ledger
}

public class MempoolTransactionStatusValueConverter : EnumTypeValueConverterBase<MempoolTransactionStatus>
{
    public static readonly Dictionary<MempoolTransactionStatus, string> Conversion = new()
    {
        { MempoolTransactionStatus.InNodeMempool, "IN_NODE_MEMPOOL" },
        { MempoolTransactionStatus.Missing, "MISSING" },
        { MempoolTransactionStatus.ResolvedButUnknownTillSyncedUp, "RESOLVED_BUT_UNKNOWN_TILL_SYNCED_UP" },
        { MempoolTransactionStatus.Failed, "FAILED" },
        { MempoolTransactionStatus.Committed, "COMMITTED" },
    };

    public MempoolTransactionStatusValueConverter()
        : base(Conversion, Invert(Conversion))
    {
    }
}

public enum MempoolTransactionFailureReason
{
    DoubleSpend,
    Timeout,
    Unknown,
    // Invalid shouldn't be possible, because they shouldn't make it to this table in the first place - mark as Unknown
}

public class MempoolTransactionFailureReasonValueConverter : EnumTypeValueConverterBase<MempoolTransactionFailureReason>
{
    private static readonly Dictionary<MempoolTransactionFailureReason, string> _conversion = new()
    {
        { MempoolTransactionFailureReason.DoubleSpend, "DOUBLE_SPEND" },
        { MempoolTransactionFailureReason.Timeout, "TIMEOUT" },
        { MempoolTransactionFailureReason.Unknown, "UNKNOWN" },
    };

    public MempoolTransactionFailureReasonValueConverter()
        : base(_conversion, Invert(_conversion))
    {
    }
}

/// <summary>
///  This stores all the data needed to construct a Gateway.TransactionInfo (alongside the other data in the DB).
/// </summary>
[DataContract(Name = "TransactionContents")]
public record GatewayTransactionContents
{
    [DataMember(Name = "actions", EmitDefaultValue = false)]
    public List<Gateway.Action> Actions { get; set; }

    [DataMember(Name = "fee", EmitDefaultValue = false)]
    public string FeePaidSubunits { get; set; }

    [DataMember(Name = "message", EmitDefaultValue = false)]
    public string? MessageHex { get; set; }

    [DataMember(Name = "confirmed_time", EmitDefaultValue = false)]
    public Instant? ConfirmedTime { get; set; }

    [DataMember(Name = "state_version", EmitDefaultValue = false)]
    public long? LedgerStateVersion { get; set; }

    public static GatewayTransactionContents Default()
    {
        return new GatewayTransactionContents { Actions = new List<Gateway.Action>(), FeePaidSubunits = string.Empty };
    }
}

/// <summary>
/// A record of transactions submitted recently by this and other nodes.
/// </summary>
[Table("mempool_transactions")]
public class MempoolTransaction
{
    private static readonly JsonSerializerSettings _transactionContentsSerializerSettings = new JsonSerializerSettings()
        .ConfigureForNodaTime(DateTimeZoneProviders.Tzdb);

    private MempoolTransaction(byte[] transactionIdentifierHash, byte[] payload, GatewayTransactionContents transactionContents)
    {
        TransactionIdentifierHash = transactionIdentifierHash;
        Payload = payload;
        SetTransactionContents(transactionContents);
    }

    // For EF Core
    private MempoolTransaction()
    {
    }

    [Key]
    [Column(name: "transaction_id")]
    [DatabaseGenerated(DatabaseGeneratedOption.None)]
    // ReSharper disable once AutoPropertyCanBeMadeGetOnly.Local - Needed for EF Core
    public byte[] TransactionIdentifierHash { get; private set; }

    /// <summary>
    /// The payload of the transaction.
    /// </summary>
    [Column("payload")]
    // ReSharper disable once AutoPropertyCanBeMadeGetOnly.Local - Needed for EF Core
    public byte[] Payload { get; private set; }

    // https://www.npgsql.org/efcore/mapping/json.html?tabs=data-annotations%2Cpoco
    [Column("transaction_contents", TypeName="jsonb")]
    public string TransactionContents { get; private set; }

    [Column("status")]
    [ConcurrencyCheck]
    public MempoolTransactionStatus Status { get; private set; }

    /// <summary>
    /// True if the transaction was submitted by this gateway. In which case, the gateway is responsible for
    /// monitoring its status in the core API, and resubmitting.
    /// </summary>
    [Column("submitted_by_this_gateway")]
    public bool SubmittedByThisGateway { get; private set; }

    /// <summary>
    /// The timestamp when the transaction was initially submitted to a node through this gateway.
    /// </summary>
    [Column("first_submitted_to_gateway_timestamp")]
    public Instant? FirstSubmittedToGatewayTimestamp { get; private set; }

    /// <summary>
    /// The timestamp when the transaction was last submitted to a node.
    /// </summary>
    [Column("last_submitted_to_gateway_timestamp")]
    public Instant? LastSubmittedToGatewayTimestamp { get; private set; }

    /// <summary>
    /// The timestamp when the transaction was last submitted to a node.
    /// </summary>
    [Column("last_submitted_to_node_timestamp")]
    public Instant? LastSubmittedToNodeTimestamp { get; private set; }

    /// <summary>
    /// The timestamp when the transaction was last submitted to a node.
    /// </summary>
    [Column("last_submitted_to_node_name")]
    public string? LastSubmittedToNodeName { get; private set; }

    [Column("submission_count")]
    public int SubmissionToNodesCount { get; private set; }

    /// <summary>
    /// The timestamp when the transaction was first seen in a node's mempool.
    /// </summary>
    [Column("first_seen_in_mempool_timestamp")]
    public Instant? FirstSeenInMempoolTimestamp { get; private set; }

    /// <summary>
    /// The timestamp when the transaction was last changed to a MISSING state.
    /// </summary>
    [Column("last_missing_from_mempool_timestamp")]
    public Instant? LastDroppedOutOfMempoolTimestamp { get; private set; }

    /// <summary>
    /// The timestamp when the transaction was committed to the DB ledger.
    /// </summary>
    [Column("commit_timestamp")]
    public Instant? CommitTimestamp { get; private set; }

    [Column("failure_reason")]
    public MempoolTransactionFailureReason? FailureReason { get; private set; }

    [Column("failure_explanation")]
    public string? FailureExplanation { get; private set; }

    [Column("failure_timestamp")]
    public Instant? FailureTimestamp { get; private set; }

    public static MempoolTransaction NewFirstSeenInMempool(
        byte[] transactionIdentifierHash,
        byte[] payload,
        GatewayTransactionContents transactionContents,
        Instant? firstSeenAt = null
    )
    {
        var mempoolTransaction = new MempoolTransaction(transactionIdentifierHash, payload, transactionContents);
        mempoolTransaction.MarkAsSeenInAMempool(firstSeenAt);
        return mempoolTransaction;
    }

    public static MempoolTransaction NewAsSubmittedForFirstTimeByGateway(
        byte[] transactionIdentifierHash,
        byte[] payload,
        string submittedToNodeName,
        GatewayTransactionContents transactionContents,
        Instant? submittedTimestamp = null
    )
    {
        var mempoolTransaction = new MempoolTransaction(transactionIdentifierHash, payload, transactionContents);

        submittedTimestamp ??= SystemClock.Instance.GetCurrentInstant();
        mempoolTransaction.MarkAsSubmittedToGateway(submittedTimestamp);

        // We assume it's been successfully submitted until we see an error and then mark it as an error then
        // This ensures the correct resubmission behaviour
        mempoolTransaction.MarkAsAssumedSuccessfullySubmittedToNode(submittedToNodeName, submittedTimestamp);

        return mempoolTransaction;
    }

    public GatewayTransactionContents GetTransactionContents()
    {
        try
        {
            return JsonConvert.DeserializeObject<GatewayTransactionContents>(
                TransactionContents,
                _transactionContentsSerializerSettings
            ) ?? GatewayTransactionContents.Default();
        }
        catch (Exception)
        {
            return GatewayTransactionContents.Default();
        }
    }

    public void MarkAsMissing(Instant? timestamp = null)
    {
        Status = MempoolTransactionStatus.Missing;
        LastDroppedOutOfMempoolTimestamp = timestamp ?? SystemClock.Instance.GetCurrentInstant();
    }

    public void MarkAsCommitted(long ledgerStateVersion, Instant ledgerCommitTimestamp)
    {
        var commitToDbTimestamp = SystemClock.Instance.GetCurrentInstant();
        Status = MempoolTransactionStatus.Committed;
        CommitTimestamp = commitToDbTimestamp;

        var transactionContents = GetTransactionContents();
        transactionContents.LedgerStateVersion = ledgerStateVersion;
        transactionContents.ConfirmedTime = ledgerCommitTimestamp;

        SetTransactionContents(transactionContents);
    }

    public void MarkAsSeenInAMempool(Instant? timestamp = null)
    {
        Status = MempoolTransactionStatus.InNodeMempool;
        FirstSeenInMempoolTimestamp ??= timestamp ?? SystemClock.Instance.GetCurrentInstant();
    }

    public void MarkAsFailed(MempoolTransactionFailureReason failureReason, string failureExplanation, Instant? timestamp = null)
    {
        Status = MempoolTransactionStatus.Failed;
        FailureReason = failureReason;
        FailureExplanation = failureExplanation;
        FailureTimestamp = timestamp ?? SystemClock.Instance.GetCurrentInstant();
    }

    public void MarkAsSubmittedToGateway(Instant? submittedAt = null)
    {
        submittedAt ??= SystemClock.Instance.GetCurrentInstant();
        SubmittedByThisGateway = true;
        FirstSubmittedToGatewayTimestamp ??= submittedAt;
        LastSubmittedToGatewayTimestamp = submittedAt;
    }

    public void MarkAsAssumedSuccessfullySubmittedToNode(string nodeSubmittedTo, Instant? submittedAt = null)
    {
        Status = MempoolTransactionStatus.InNodeMempool;
        RecordSubmission(nodeSubmittedTo, submittedAt);
    }

    public void MarkAsFailedAfterSubmittedToNode(string nodeSubmittedTo, MempoolTransactionFailureReason failureReason, string failureExplanation, Instant? submittedAt = null)
    {
        MarkAsFailed(failureReason, failureExplanation);
        RecordSubmission(nodeSubmittedTo, submittedAt);
    }

    public void MarkAsResolvedButUnknownAfterSubmittedToNode(string nodeSubmittedTo, Instant? submittedAt = null)
    {
        Status = MempoolTransactionStatus.ResolvedButUnknownTillSyncedUp;
        RecordSubmission(nodeSubmittedTo, submittedAt);
    }

    private void RecordSubmission(string nodeSubmittedTo, Instant? submittedAt = null)
    {
        LastSubmittedToNodeTimestamp = submittedAt ?? SystemClock.Instance.GetCurrentInstant();
        LastSubmittedToNodeName = nodeSubmittedTo;
        SubmissionToNodesCount += 1;
    }

    private void SetTransactionContents(GatewayTransactionContents transactionContents)
    {
        TransactionContents = JsonConvert.SerializeObject(transactionContents, _transactionContentsSerializerSettings);
    }
}

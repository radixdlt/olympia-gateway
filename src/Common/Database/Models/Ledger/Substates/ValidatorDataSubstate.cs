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

using Common.Addressing;
using Common.Database.Models.Ledger.Normalization;
using Common.Database.ValueConverters;
using Microsoft.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations.Schema;

using Core = RadixCoreApi.Generated.Model;
using Db = Common.Database.Models.Ledger.Substates;

namespace Common.Database.Models.Ledger.Substates;

public enum ValidatorDataSubstateType
{
    ValidatorData,
    ValidatorMetaData,
    ValidatorAllowDelegation,
    PreparedValidatorRegistered,
    PreparedValidatorFee,
    PreparedValidatorOwner,
}

public class ValidatorDataSubstateTypeValueConverter : EnumTypeValueConverterBase<ValidatorDataSubstateType>
{
    private static readonly Dictionary<ValidatorDataSubstateType, string> _conversion = new()
    {
        { ValidatorDataSubstateType.ValidatorData, "DATA" },
        { ValidatorDataSubstateType.ValidatorMetaData, "METADATA" },
        { ValidatorDataSubstateType.ValidatorAllowDelegation, "ALLOW_DELEGATION" },
        { ValidatorDataSubstateType.PreparedValidatorRegistered, "PREPARED_REGISTERED" },
        { ValidatorDataSubstateType.PreparedValidatorFee, "PREPARED_FEE" },
        { ValidatorDataSubstateType.PreparedValidatorOwner, "PREPARED_OWNER" },
    };

    public ValidatorDataSubstateTypeValueConverter()
        : base(_conversion, Invert(_conversion))
    {
    }
}

/// <summary>
/// Combines ValidatorStakeData, ValidatorMetaData, ValidatorAllowDelegation,
/// PreparedValidatorRegistered, PreparedValidatorFee, PreparedValidatorOwner.
/// </summary>
[Index(nameof(ValidatorId))]
[Table("validator_data_substates")]
public class ValidatorDataSubstate : DataSubstateBase
{
    [Column(name: "validator_id")]
    public long ValidatorId { get; set; }

    [ForeignKey(nameof(ValidatorId))]
    public Validator Validator { get; set; }

    [Column(name: "type")]
    public ValidatorDataSubstateType Type { get; set; }

    [Column("effective_epoch")]
    public long? EffectiveEpoch { get; set; }

    // These are all [Owned] types below - exactly one of these will be present on each
    public ValidatorData? ValidatorData { get; set; }

    public ValidatorMetadata? ValidatorMetaData { get; set; }

    public ValidatorAllowDelegation? ValidatorAllowDelegation { get; set; }

    public PreparedValidatorRegistered? PreparedValidatorRegistered { get; set; }

    public PreparedValidatorFee? PreparedValidatorFee { get; set; }

    public PreparedValidatorOwner? PreparedValidatorOwner { get; set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="ValidatorDataSubstate"/> class.
    /// The SubstateBase properties should be set separately.
    /// </summary>
    public ValidatorDataSubstate(Validator validator, ValidatorDataSubstateType type, long? effectiveEpoch, ValidatorData? validatorData, ValidatorMetadata? validatorMetaData, ValidatorAllowDelegation? validatorAllowDelegation, PreparedValidatorRegistered? preparedValidatorRegistered, PreparedValidatorFee? preparedValidatorFee, PreparedValidatorOwner? preparedValidatorOwner)
    {
        Validator = validator;
        Type = type;
        EffectiveEpoch = effectiveEpoch;
        ValidatorData = validatorData;
        ValidatorMetaData = validatorMetaData;
        ValidatorAllowDelegation = validatorAllowDelegation;
        PreparedValidatorRegistered = preparedValidatorRegistered;
        PreparedValidatorFee = preparedValidatorFee;
        PreparedValidatorOwner = preparedValidatorOwner;
    }

    private ValidatorDataSubstate()
    {
    }

    public bool SubstateMatches(ValidatorDataSubstate otherSubstate)
    {
        return Validator == otherSubstate.Validator
               && Type == otherSubstate.Type
               && EffectiveEpoch == otherSubstate.EffectiveEpoch
               && ValidatorData == otherSubstate.ValidatorData
               && ValidatorMetaData == otherSubstate.ValidatorMetaData
               && ValidatorAllowDelegation == otherSubstate.ValidatorAllowDelegation
               && PreparedValidatorRegistered == otherSubstate.PreparedValidatorRegistered
               && PreparedValidatorFee == otherSubstate.PreparedValidatorFee
               && PreparedValidatorOwner == otherSubstate.PreparedValidatorOwner;
    }
}

public record ValidatorDataObjects(
    Core.ValidatorData? ValidatorData,
    Core.ValidatorMetadata? ValidatorMetadata,
    Core.ValidatorAllowDelegation? ValidatorAllowDelegation,
    Core.PreparedValidatorRegistered? PreparedValidatorRegistered,
    Core.PreparedValidatorFee? PreparedValidatorFee,
    Core.PreparedValidatorOwner? PreparedValidatorOwner
)
{
    public ValidatorDataObjects()
        : this(null, null, null, null, null, null)
    {
    }

    public ValidatorDataSubstate ToDbValidatorData(Validator validator, Account? validatorOwner)
    {
        var type = ValidatorData != null ? ValidatorDataSubstateType.ValidatorData
            : ValidatorMetadata != null ? ValidatorDataSubstateType.ValidatorMetaData
            : ValidatorAllowDelegation != null ? ValidatorDataSubstateType.ValidatorAllowDelegation
            : PreparedValidatorRegistered != null ? ValidatorDataSubstateType.PreparedValidatorRegistered
            : PreparedValidatorFee != null ? ValidatorDataSubstateType.PreparedValidatorFee
            : PreparedValidatorOwner != null ? ValidatorDataSubstateType.PreparedValidatorOwner
            : throw new ArgumentException("At least one substate type has to be non-null");

        var effectiveEpoch = PreparedValidatorRegistered?.Epoch
                             ?? PreparedValidatorFee?.Epoch
                             ?? PreparedValidatorOwner?.Epoch;

        return new ValidatorDataSubstate(
            validator: validator,
            type: type,
            effectiveEpoch: effectiveEpoch,
            validatorData: Db.ValidatorData.From(ValidatorData, validatorOwner),
            validatorMetaData: Db.ValidatorMetadata.From(ValidatorMetadata),
            validatorAllowDelegation: Db.ValidatorAllowDelegation.From(ValidatorAllowDelegation),
            preparedValidatorRegistered: Db.PreparedValidatorRegistered.From(PreparedValidatorRegistered),
            preparedValidatorFee: Db.PreparedValidatorFee.From(PreparedValidatorFee),
            preparedValidatorOwner: Db.PreparedValidatorOwner.From(PreparedValidatorOwner, validatorOwner)
        );
    }
}

public record OutputValidatorData(string OwnerAddress, bool IsRegistered, decimal FeePercentage);

[Owned]
// Aka ValidatorStakeData in the engine
public record ValidatorData
{
    [Column(name: "owner_id")]
    public long OwnerId { get; set; }

    [ForeignKey(nameof(OwnerId))]
    public Account Owner { get; set; }

    [Column(name: "is_registered")]
    public bool IsRegistered { get; set; }

    [Column(name: "fee_percentage")]
    public decimal FeePercentage { get; set; }

    public OutputValidatorData ToOutputData(Func<long, string> ownerAddressMap)
    {
        return new OutputValidatorData(
            OwnerAddress: ownerAddressMap(OwnerId),
            IsRegistered: IsRegistered,
            FeePercentage: FeePercentage
        );
    }

    public static ValidatorData? From(Core.ValidatorData? apiModel, Account? validatorOwner)
    {
        return apiModel == null ? null
            : new ValidatorData
            {
                OwnerId = validatorOwner!.Id,
                Owner = validatorOwner,
                IsRegistered = apiModel.Registered,
                FeePercentage = ((decimal)apiModel.Fee) / 100,
            };
    }

    public static OutputValidatorData GetDefaultOutputData(AddressHrps addressHrps, byte[] validatorAddressPublicKey)
    {
        return new OutputValidatorData(
            OwnerAddress: RadixBech32.GenerateAccountAddress(addressHrps.AccountHrp, validatorAddressPublicKey),
            IsRegistered: false,
            FeePercentage: 0
        );
    }
}

[Owned]
public record ValidatorMetadata
{
    [Column(name: "name")]
    public string Name { get; set; }

    [Column(name: "url")]
    public string Url { get; set; }

    public static ValidatorMetadata? From(Core.ValidatorMetadata? apiModel)
    {
        return apiModel == null ? null
            : new ValidatorMetadata { Name = apiModel.Name, Url = apiModel.Url };
    }

    public static ValidatorMetadata GetDefault()
    {
        return new ValidatorMetadata { Name = string.Empty, Url = string.Empty };
    }
}

[Owned]
public record ValidatorAllowDelegation
{
    [Column(name: "allow_delegation")]
    public bool AllowDelegation { get; set; }

    public static ValidatorAllowDelegation? From(Core.ValidatorAllowDelegation? apiModel)
    {
        return apiModel == null ? null
            : new ValidatorAllowDelegation { AllowDelegation = apiModel.AllowDelegation };
    }

    public static ValidatorAllowDelegation GetDefault()
    {
        return new ValidatorAllowDelegation { AllowDelegation = false };
    }
}

public record OutputPreparedValidatorRegistered(long EffectiveEpoch, bool IsRegistered);

[Owned]
// NB - This has a (virtual) default of PreparedIsRegistered=False, EffectiveEpoch=0
//      This virtual default can get downed without being created; and after the preparation completes,
//      an UP substate with this default is explicitly re-created.
public record PreparedValidatorRegistered
{
    [Column(name: "prepared_is_registered")]
    public bool PreparedIsRegistered { get; set; }

    public static PreparedValidatorRegistered? From(Core.PreparedValidatorRegistered? apiModel)
    {
        return apiModel == null ? null
            : new PreparedValidatorRegistered { PreparedIsRegistered = apiModel.Registered };
    }

    public static OutputPreparedValidatorRegistered? GetIfActive(ValidatorDataSubstate? dataSubstate)
    {
        return dataSubstate?.PreparedValidatorRegistered == null
               || dataSubstate.EffectiveEpoch is null or 0
            ? null
            : new OutputPreparedValidatorRegistered(
                dataSubstate.EffectiveEpoch.Value,
                dataSubstate.PreparedValidatorRegistered.PreparedIsRegistered
            );
    }
}

public record OutputPreparedValidatorFee(long EffectiveEpoch, decimal FeePercentage);

[Owned]
public record PreparedValidatorFee
{
    [Column(name: "prepared_fee_percentage")]
    public decimal PreparedFeePercentage { get; set; }

    public static PreparedValidatorFee? From(Core.PreparedValidatorFee? apiModel)
    {
        return apiModel == null ? null
            : new PreparedValidatorFee { PreparedFeePercentage = ((decimal)apiModel.Fee) / 100 };
    }

    public static OutputPreparedValidatorFee? GetIfActive(ValidatorDataSubstate? dataSubstate)
    {
        return dataSubstate?.PreparedValidatorFee == null
               || dataSubstate.EffectiveEpoch is null or 0
            ? null
            : new OutputPreparedValidatorFee(
                dataSubstate.EffectiveEpoch.Value,
                dataSubstate.PreparedValidatorFee.PreparedFeePercentage
            );
    }
}

public record OutputPreparedValidatorOwner(long EffectiveEpoch, string OwnerAddress);

[Owned]
public record PreparedValidatorOwner
{
    [Column(name: "prepared_owner_id")]
    public long PreparedOwnerId { get; set; }

    [ForeignKey(nameof(PreparedOwnerId))]
    public Account PreparedOwner { get; set; }

    public static PreparedValidatorOwner? From(Core.PreparedValidatorOwner? apiModel, Account? validatorOwner)
    {
        return apiModel == null ? null
            : new PreparedValidatorOwner
            {
                PreparedOwnerId = validatorOwner!.Id,
                PreparedOwner = validatorOwner,
            };
    }

    public static OutputPreparedValidatorOwner? GetIfActive(ValidatorDataSubstate? dataSubstate, Func<long, string> accountAddressMap)
    {
        return dataSubstate?.PreparedValidatorOwner == null
               || dataSubstate.EffectiveEpoch is null or 0
            ? null
            : new OutputPreparedValidatorOwner(
                dataSubstate.EffectiveEpoch.Value,
                accountAddressMap(dataSubstate.PreparedValidatorOwner.PreparedOwnerId)
            );
    }
}

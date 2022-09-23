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

// ReSharper disable CommentTypo
// ReSharper disable StringLiteralTypo
// ReSharper disable IdentifierTypo
/* The above is a fix for ReShaper not liking the work "Bech" */

using Common.StaticHelpers;
using System.Text;
using System.Text.RegularExpressions;

namespace Common.Addressing;

public record RadixBech32Data(string Hrp, byte[] Data, Bech32.Variant Variant);

public record RadixEngineAddressData(RadixEngineAddressType Type, byte[] AddressBytes);

public enum RadixEngineAddressType : byte
{
    SYSTEM = 0,
    NATIVE_TOKEN = 1,
    HASHED_KEY = 3,
    PUB_KEY = 4,
}

public static class RadixBech32
{
    public const int TruncatedSymbolLength = 11;
    public const int HashedKeyTruncatedBytesLength = 26;
    public const int CompressedPublicKeyBytesLength = 33;
    public static readonly Regex ValidResourceSymbolRegex = new("^[a-z0-9]{1,35}$");
    private const Bech32.Variant DefaultVariant = Bech32.Variant.Bech32;

    public static string GenerateValidatorAddress(string validatorHrp, byte[] compressedPublicKey, Bech32.Variant variant = DefaultVariant)
    {
        return GeneratePublicKeyNonRadixEngineAddress(validatorHrp, compressedPublicKey, variant);
    }

    public static string GenerateAccountAddress(string accountHrp, byte[] compressedPublicKey, Bech32.Variant variant = DefaultVariant)
    {
        return GeneratePublicKeyRadixEngineAddress(accountHrp, compressedPublicKey, variant);
    }

    public static string GenerateResourceAddress(byte[] compressedAccountPublicKey, string symbol, string resourceHrpSuffix, Bech32.Variant variant = DefaultVariant)
    {
        var shortSymbol = symbol.Substring(0, Math.Min(symbol.Length, TruncatedSymbolLength));

        return GenerateHashedKeyRadixEngineAddress(
            $"{shortSymbol}{resourceHrpSuffix}",
            symbol,
            compressedAccountPublicKey,
            variant
        );
    }

    public static string GeneratePublicKeyNonRadixEngineAddress(string hrp, byte[] compressedPublicKey, Bech32.Variant variant = DefaultVariant)
    {
        if (compressedPublicKey.Length != CompressedPublicKeyBytesLength)
        {
            throw new AddressException($"Compressed public key must be of length {CompressedPublicKeyBytesLength}");
        }

        return EncodeNonRadixEngineAddress(hrp, compressedPublicKey, variant);
    }

    public static string GeneratePublicKeyRadixEngineAddress(string hrp, byte[] compressedPublicKey, Bech32.Variant variant = DefaultVariant)
    {
        if (compressedPublicKey.Length != CompressedPublicKeyBytesLength)
        {
            throw new AddressException($"Compressed public key must be of length {CompressedPublicKeyBytesLength}");
        }

        return EncodeRadixEngineAddress(RadixEngineAddressType.PUB_KEY, hrp, compressedPublicKey, variant);
    }

    public static string GenerateHashedKeyRadixEngineAddress(string hrp, string name, byte[] compressedPublicKey, Bech32.Variant variant = DefaultVariant)
    {
        if (compressedPublicKey.Length != CompressedPublicKeyBytesLength)
        {
            throw new AddressException($"Compressed public key must be of length {CompressedPublicKeyBytesLength}");
        }

        if (name.Length is < 1 or > 35)
        {
            throw new AddressException("Hashed key name must be must be between 1 and 35 characters");
        }

        // Create Hash Source which is compressedPublicKey||utf8NameBytes
        var nameBytes = Encoding.UTF8.GetBytes(name);
        var hashSourceLength = compressedPublicKey.Length + nameBytes.Length;
        Span<byte> hashSource = stackalloc byte[hashSourceLength];
        compressedPublicKey.CopyTo(hashSource);
        nameBytes.CopyTo(hashSource[compressedPublicKey.Length..]);

        // Create Sha256(Sha256(compressedPublicKey||utf8NameBytes)) and then extract the last 26 bytes of the hash
        Span<byte> generatedHash = stackalloc byte[32];
        HashingHelper.Sha256Twice(hashSource, generatedHash);
        Span<byte> shortenedHash = generatedHash[(32 - HashedKeyTruncatedBytesLength)..32];

        return EncodeRadixEngineAddress(RadixEngineAddressType.HASHED_KEY, hrp, shortenedHash, variant);
    }

    public static string GenerateXrdAddress(string resourceHrpSuffix, Bech32.Variant variant = DefaultVariant)
    {
        return EncodeRadixEngineAddress(RadixEngineAddressType.NATIVE_TOKEN, $"xrd{resourceHrpSuffix}", Array.Empty<byte>(), variant);
    }

    public static string EncodeRadixEngineAddress(RadixEngineAddressType type, string hrp, ReadOnlySpan<byte> addressData, Bech32.Variant variant = DefaultVariant)
    {
        Span<byte> engineAddressBytes = stackalloc byte[1 + addressData.Length];
        engineAddressBytes[0] = (byte)type;
        addressData.CopyTo(engineAddressBytes[1..]);
        return Bech32EncodeRawAddressData(hrp, engineAddressBytes, variant);
    }

    public static string EncodeNonRadixEngineAddress(string hrp, ReadOnlySpan<byte> addressBytes, Bech32.Variant variant = DefaultVariant)
    {
        return Bech32EncodeRawAddressData(hrp, addressBytes, variant);
    }

    public static string Bech32EncodeRawAddressData(string hrp, ReadOnlySpan<byte> addressData, Bech32.Variant variant = DefaultVariant)
    {
        return Bech32.EncodeFromRawData(hrp, EncodeAddressDataInBase32(addressData), variant);
    }

    public static RadixBech32Data Decode(string encoded)
    {
        var (hrp, rawBase32Data, variant) = Bech32.DecodeToRawData(encoded);
        var addressData = DecodeBase32IntoAddressData(rawBase32Data);
        if (addressData.Length == 0)
        {
            throw new AddressException("The Bech32 address has no data");
        }

        return new RadixBech32Data(hrp, addressData, variant);
    }

    public static void ValidatePublicKeyLength(byte[] compressedPublicKey)
    {
        if (compressedPublicKey.Length != CompressedPublicKeyBytesLength)
        {
            throw new AddressException(
                $"Compressed public key should have byte length {CompressedPublicKeyBytesLength} but this address has length {compressedPublicKey.Length}"
            );
        }
    }

    public static RadixEngineAddressData ExtractRadixEngineAddressData(byte[] addressData)
    {
        var typeByte = addressData[0];
        if (!Enum.IsDefined(typeof(RadixEngineAddressType), typeByte))
        {
            throw new AddressException($"The Bech32 address type {typeByte} is not recognised");
        }

        var addressBytes = addressData.Length > 1 ? addressData[1..] : Array.Empty<byte>();

        var type = (RadixEngineAddressType)typeByte;

        switch (type)
        {
            case RadixEngineAddressType.SYSTEM:
                AssertDataOfLength(type, addressBytes, 0);
                break;
            case RadixEngineAddressType.NATIVE_TOKEN:
                AssertDataOfLength(type, addressBytes, 0);
                break;
            case RadixEngineAddressType.HASHED_KEY:
                AssertDataOfLength(type, addressBytes, HashedKeyTruncatedBytesLength);
                break;
            case RadixEngineAddressType.PUB_KEY:
                AssertDataOfLength(type, addressBytes, CompressedPublicKeyBytesLength);
                break;
            default:
                throw new ArgumentOutOfRangeException();
        }

        return new RadixEngineAddressData(type, addressBytes);
    }

    private static void AssertDataOfLength(RadixEngineAddressType type, IReadOnlyCollection<byte> addressBytes, int expectedLength)
    {
        if (addressBytes.Count != expectedLength)
        {
            throw new AddressException(
                $"Address of RE type {type} should have byte length {expectedLength} but this address has length {addressBytes}"
            );
        }
    }

    /// <summary>
    /// Defines how the 5-bit per byte (base32 per byte) data should be decoded.
    /// This will likely making use of ConvertBits to unpack to 8 bits per byte.
    /// </summary>
    private static byte[] DecodeBase32IntoAddressData(ReadOnlySpan<byte> base32EncodedData)
    {
        return Bech32.ConvertBits(base32EncodedData, 5, 8, false);
    }

    /// <summary>
    /// Defines how the data should be encoded as 5-bits per byte (base32 per byte) for the Bech32 data part.
    /// This will likely making use of ConvertBits to convert from 8 bits per byte to 5 bits per byte.
    /// </summary>
    private static ReadOnlySpan<byte> EncodeAddressDataInBase32(ReadOnlySpan<byte> dataToEncode)
    {
        return Bech32.ConvertBits(dataToEncode, 8, 5, true);
    }
}

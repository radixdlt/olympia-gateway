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
using Xunit;

namespace Tests.MiniUnitTests.Common.Addressing;

public class RadixBech32Tests
{
    [Theory]
    [InlineData("rdx1qspc9xtaqmquy88jvvuadjleudnsk0tt8dlhuwmcfv4zlqlya8ny3lc5jarf6")] // Radix Mainnet Wallet
    [InlineData("rv1qf2x63qx4jdaxj83kkw2yytehvvmu6r2xll5gcp6c9rancmrfsgfwttnczx")] // Radix Validator
    [InlineData("xrd_rr1qy5wfsfh")] // Radix Token definition Address (XRD)
    [InlineData("usdc_rb1qvqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gwwwd")] // Radix Test Token definition Address
    [InlineData("rn1qwa45jjf40vuf9xlq85xym86yegnm95h3g8d4lul5hskrws9gm6ykyx7hsf")] // Radix Node Address
    public void WhenGiven_EncodedStringWithValidRadixAddress_DecodeAndReencodeIsIdentity(string encodedString)
    {
        var decodedData = RadixBech32.Decode(encodedString);

        var reEncodedString = RadixBech32.Bech32EncodeRawAddressData(decodedData.Hrp, decodedData.Data, decodedData.Variant);
        Assert.Equal(encodedString.ToLowerInvariant(), reEncodedString);
    }

    [Theory]
    [InlineData("rdx1qspc9xtaqmquy88jvvuadjleudnsk0tt8dlhuwmcfv4zlqlya8ny3lc5jarf6", "040382997D06C1C21CF26339D6CBF9E3670B3D6B3B7F7E3B784B2A2F83E4E9E648FF")] // Radix Mainnet Wallet
    [InlineData("rv1qf2x63qx4jdaxj83kkw2yytehvvmu6r2xll5gcp6c9rancmrfsgfwttnczx", "02546D4406AC9BD348F1B59CA21179BB19BE686A37FF44603AC147D9E3634C1097")] // Radix Validator
    [InlineData("xrd_rr1qy5wfsfh", "01")] // Radix Token definition Address (XRD)
    [InlineData("usdc_rb1qvqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gwwwd", "030000000000000000000000000000000000000000000000000000")] // Radix Test Token definition Address
    [InlineData("rn1qwa45jjf40vuf9xlq85xym86yegnm95h3g8d4lul5hskrws9gm6ykyx7hsf", "03BB5A4A49ABD9C494DF01E8626CFA26513D96978A0EDAFF9FA5E161BA0546F44B")] // Radix Node Address
    public void WhenGiven_EncodedStringWithValidRadixAddress_DecodeGivesAddress(string encodedString, string expectedAddress)
    {
        var decodedData = RadixBech32.Decode(encodedString);
        Assert.Equal(expectedAddress, Convert.ToHexString(decodedData.Data));
    }

    [Theory]
    [InlineData("012343925a206b9d3d7513e145a4b42741ac22c7d081ffc511420e1234e4372483", "verylongsymbol", "_rb", "verylongsym_rb")]
    [InlineData("c27cee88dd2883a5467cac7687a5cf02e22c93f39fbc6adac342a8baf5ceee80cb", "anotherlongsymbol", "_rr", "anotherlong_rr")]
    public void GivenASymbol_WhenItIsTooLong_ThenTheHrpWillBeTruncated(string pubkey, string symbol, string suffix, string expectedHrp)
    {
        var bech32 = RadixBech32.Decode(RadixBech32.GenerateResourceAddress(Convert.FromHexString(pubkey), symbol, suffix));
        Assert.Equal(bech32.Hrp, expectedHrp);
    }

    [Theory]
    [InlineData("c27cee88dd2883a5467cac7687a5cf02e22c93f39fbc6adac342a8baf5ceee80cb", "anotherlongsymbol", "anotherlong", "_rr", "anotherlong_rr")]
    [InlineData("1552d216270b409ebe51895c9f02eef3b76553feb4fd6ea2c60391ca8bfb89a089", "truncatedsymbolone", "truncatedsymboltwo", "_rb", "truncatedsy_rb")]
    public void GivenDifferentSymbols_WhenTheyAreTruncatedTheSame_ThenTheResultingAddressWillBeStillDifferent(string pubkey, string firstSymbol, string secondSymbol, string suffix, string expectedTruncatedHrp)
    {
        var firstBech32 = RadixBech32.Decode(RadixBech32.GenerateResourceAddress(Convert.FromHexString(pubkey), firstSymbol, suffix));
        var secondBech32 = RadixBech32.Decode(RadixBech32.GenerateResourceAddress(Convert.FromHexString(pubkey), secondSymbol, suffix));

        Assert.Equal(firstBech32.Hrp, secondBech32.Hrp);
        Assert.Equal(firstBech32.Hrp, expectedTruncatedHrp);
        Assert.NotEqual(firstSymbol, secondSymbol);
        Assert.NotEqual(firstBech32.Data, secondBech32.Data);
    }

    public static IEnumerable<object[]> Invalid_Bech32Strings => new List<object[]>
    {
        new object[] { (char)0x20 + "1nwldj5" }, // HRP character out of range
        new object[] { (char)0x7F + "1axkwrx" }, // HRP character out of range
        new object[] { (char)0x80 + "1eym55h" }, // HRP character out of range
        new object[] { "de1lg7wt" + (char)0xFF }, // Invalid character in checksum
        new object[] { "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx" }, // HRP character out of range
        new object[] { "pzry9x0s0muk" }, // No separator character
        new object[] { "1pzry9x0s0muk" }, // Empty HRP
        new object[] { "x1b4n0q5v" }, // Invalid data character
        new object[] { "li1dgmt3" }, // Too short checksum
        new object[] { "A1G7SGD8" }, // checksum calculated with uppercase form of HRP
        new object[] { "10a06t8" }, // empty HRP
        new object[] { "vb1qvx0emaq0tua6md7wu9c047mm5krrwnlfl8c7ws3jm2s9uf4vxcyvrwrazz" }, // Bad checksum
    };

    [Theory]
    [MemberData(nameof(Invalid_Bech32Strings))]
    public void WhenGiven_InvalidEncodedString_DecodeThrows(string encodedString)
    {
        Assert.Throws<AddressException>(() => Bech32.DecodeToRawData(encodedString));
    }
}

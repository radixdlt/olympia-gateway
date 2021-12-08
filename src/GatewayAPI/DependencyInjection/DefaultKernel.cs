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

using GatewayAPI.ApiSurface;
using GatewayAPI.Configuration;
using GatewayAPI.CoreCommunications;
using GatewayAPI.Database;
using GatewayAPI.Fallback;
using GatewayAPI.Services;
using Microsoft.EntityFrameworkCore;
using System.Net;

namespace GatewayAPI.DependencyInjection;

public class DefaultKernel
{
    public void ConfigureServices(HostBuilderContext hostBuilderContext, IServiceCollection services)
    {
        // Globally-Scoped services
        AddGlobalScopedServices(services);
        AddReadOnlyDatabaseContext(hostBuilderContext, services);

        // Request scoped services
        AddRequestScopedServices(services);
        AddCoreApiServices(services);
        AddFallbackApiServices(services);
    }

    private void AddGlobalScopedServices(IServiceCollection services)
    {
        services.AddSingleton<INetworkGatewayConfiguration, NetworkGatewayConfiguration>();
        services.AddSingleton<INetworkConfigurationProvider, NetworkConfigurationProvider>();
        services.AddSingleton<IValidations, Validations>();
        services.AddSingleton<IExceptionHandler, ExceptionHandler>();
        services.AddSingleton<IValidationErrorHandler, ValidationErrorHandler>();
        services.AddSingleton<ICoreApiHandler, CoreApiHandler>();
    }

    private void AddRequestScopedServices(IServiceCollection services)
    {
        services.AddScoped<ILedgerStateQuerier, LedgerStateQuerier>();
        services.AddScoped<IAccountQuerier, AccountQuerier>();
        services.AddScoped<ITokenQuerier, TokenQuerier>();
        services.AddScoped<IValidatorQuerier, ValidatorQuerier>();
        services.AddScoped<IConstructionAndSubmissionService, ConstructionAndSubmissionService>();
    }

    private void AddCoreApiServices(IServiceCollection services)
    {
        // NB - AddHttpClient is essentially like AddTransient, except it provides a HttpClient from the HttpClientFactory
        // See https://docs.microsoft.com/en-us/dotnet/architecture/microservices/implement-resilient-applications/use-httpclientfactory-to-implement-resilient-http-requests
        services.AddHttpClient<ICoreApiHandler, CoreApiHandler>()
            .ConfigurePrimaryHttpMessageHandler(serviceProvider => ConfigureHttpClientHandler(
                serviceProvider,
                "DisableCoreApiHttpsCertificateChecks",
                "CoreApiHttpProxyAddress"
            ));
    }

    private void AddFallbackApiServices(IServiceCollection services)
    {
        // NB - AddHttpClient is essentially like AddTransient, except it provides a HttpClient from the HttpClientFactory
        // See https://docs.microsoft.com/en-us/dotnet/architecture/microservices/implement-resilient-applications/use-httpclientfactory-to-implement-resilient-http-requests
        services.AddHttpClient<IFallbackGatewayApiProvider, FallbackGatewayApiProvider>()
            .ConfigurePrimaryHttpMessageHandler(serviceProvider => ConfigureHttpClientHandler(
                serviceProvider,
                "DisableFallbackGatewayApiHttpsCertificateChecks",
                "FallbackGatewayApiHttpProxyAddress"
            ));
    }

    private void AddReadOnlyDatabaseContext(HostBuilderContext hostContext, IServiceCollection services)
    {
        services.AddDbContext<GatewayReadOnlyDbContext>(options =>
        {
            // https://www.npgsql.org/efcore/index.html
            options.UseNpgsql(hostContext.Configuration.GetConnectionString("ReadOnlyDbContext"));
        });
    }

    private HttpClientHandler ConfigureHttpClientHandler(
        IServiceProvider serviceProvider,
        string disableApiChecksConfigParameterName,
        string httpProxyAddressConfigParameterName
    )
    {
        var httpClientHandler = new HttpClientHandler();

        var configuration = serviceProvider.GetRequiredService<IConfiguration>();
        var disableCertificateChecks = configuration.GetValue<bool>(disableApiChecksConfigParameterName);
        var httpProxyAddress = configuration.GetValue<string?>(httpProxyAddressConfigParameterName);

        if (disableCertificateChecks)
        {
            httpClientHandler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
        }

        if (!string.IsNullOrWhiteSpace(httpProxyAddress))
        {
            httpClientHandler.Proxy = new WebProxy(httpProxyAddress);
        }

        return httpClientHandler;
    }
}

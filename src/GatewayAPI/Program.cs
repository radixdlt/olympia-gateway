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

// StyleCop getting confused with flat Program.cs
#pragma warning disable SA1516

using Common.Database;
using GatewayAPI.ApiSurface;
using GatewayAPI.Database;
using GatewayAPI.DependencyInjection;
using GatewayAPI.Services;
using Prometheus;

var builder = WebApplication.CreateBuilder(args);
var hostBuilder = builder.Host;

/* Read in other configuration */

hostBuilder.ConfigureAppConfiguration((context, config) =>
{
    config.AddEnvironmentVariables("RADIX_NG_API__");
    if (args is { Length: > 0 })
    {
        config.AddCommandLine(args);
    }

    if (context.HostingEnvironment.IsDevelopment())
    {
        // As an easier alternative to developer secrets -- this file is in .gitignore to prevent source controlling
        config.AddJsonFile("appsettings.PersonalOverrides.json", optional: true, reloadOnChange: true);
    }

    var customConfigurationPath = config.Build()
        .GetValue<string?>("CustomJsonConfigurationFilePath", null);

    if (customConfigurationPath != null)
    {
        config.AddJsonFile(customConfigurationPath, false, true);
    }
});

/* Configure services / dependency injection */

hostBuilder.ConfigureServices(new DefaultKernel().ConfigureServices);
hostBuilder.ConfigureLogging((_, loggingBuilder) =>
{
    loggingBuilder.AddConsole();
});

var servicesBuilder = builder.Services;

servicesBuilder
    .AddControllers(options =>
    {
        options.Filters.Add<ExceptionFilter>();
    })
    /* See https://stackoverflow.com/a/58438608 - Ensure the API respects the JSON schema names from the generated spec */
    .AddNewtonsoftJson()
    .ConfigureApiBehaviorOptions(options =>
    {
        options.InvalidModelStateResponseFactory = context =>
        {
            var validationErrorHandler = context.HttpContext.RequestServices.GetRequiredService<IValidationErrorHandler>();
            return validationErrorHandler.GetClientError(context);
        };
    });

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
servicesBuilder.AddEndpointsApiExplorer();
servicesBuilder.AddSwaggerGen();
servicesBuilder.AddSwaggerGenNewtonsoftSupport();

servicesBuilder.AddCors(options =>
{
    options.AddDefaultPolicy(corsPolicyBuilder =>
    {
        corsPolicyBuilder.AllowAnyOrigin().AllowAnyMethod();
    });
});

servicesBuilder.AddHealthChecks()
    .AddDbContextCheck<GatewayReadOnlyDbContext>("readonly_database_connection_check")
    .AddDbContextCheck<GatewayReadWriteDbContext>("readwrite_database_connection_check")
    .ForwardToPrometheus();

var app = builder.Build();

var services = app.Services;

var configuration = services.GetRequiredService<IConfiguration>();
var programLogger = services.GetRequiredService<ILogger<Program>>();
var isSwaggerEnabled = configuration.GetValue<bool>("EnableSwagger");

// https://docs.microsoft.com/en-us/aspnet/core/host-and-deploy/health-checks?view=aspnetcore-6.0
app.MapHealthChecks("/health");

// Configure the HTTP request pipeline.
if (isSwaggerEnabled)
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthorization();
app.MapControllers();
app.UseHttpMetrics();
app.UseCors();

StartMetricServer();

await EnsureCanConnectToDatabase(app);
await LoadNetworkConfiguration(app);

await app.RunAsync();

/* Methods */

async Task EnsureCanConnectToDatabase(WebApplication webApplication)
{
    var maxWaitForDbMs = webApplication.Configuration.GetValue("MaxWaitForDbOnStartupMs", 0);
    await ConnectionHelpers.TryWaitForExistingDb<GatewayReadOnlyDbContext>(webApplication.Services, maxWaitForDbMs);
}

async Task LoadNetworkConfiguration(WebApplication webApplication)
{
    using var scope = webApplication.Services.CreateScope();
    var networkConfigurationProvider = scope.ServiceProvider.GetRequiredService<INetworkConfigurationProvider>();

    while (true)
    {
        try
        {
            await networkConfigurationProvider
                .LoadNetworkConfigurationFromDatabase(
                    scope.ServiceProvider.GetRequiredService<GatewayReadOnlyDbContext>(),
                    CancellationToken.None
                );
            break;
        }
        catch (Exception exception)
        {
            programLogger.LogWarning(exception, "Error fetching network configuration - perhaps the data aggregator hasn't committed yet? Will try again in 2 seconds");
            await Task.Delay(2000);
        }
    }
}

void StartMetricServer()
{
    var metricPort = configuration.GetValue<int>("PrometheusMetricsPort");
    if (metricPort != 0)
    {
        programLogger.LogInformation("Starting metrics server on port http://localhost:{MetricPort}", metricPort);
        new KestrelMetricServer(port: metricPort).Start();
    }
    else
    {
        programLogger.LogInformation("PrometheusMetricsPort not configured - not starting metric server");
    }
}

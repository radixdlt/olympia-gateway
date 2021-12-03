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
using Microsoft.AspNetCore.Cors.Infrastructure;

var builder = WebApplication.CreateBuilder(args);
var host = builder.Host;
var services = builder.Services;

/* Read in other configuration */

host.ConfigureAppConfiguration((_, config) =>
{
    config.AddEnvironmentVariables("RADIX_NG_API__");
    if (args is { Length: > 0 })
    {
        config.AddCommandLine(args);
    }
});

/* Configure services / dependency injection */

host.ConfigureServices(new DefaultKernel().ConfigureServices);

services
    .AddControllers(options =>
    {
        options.Filters.Add<ExceptionFilter>();
    })
    /* See https://stackoverflow.com/a/58438608 - Ensure the API respects the JSON schema names from the generated spec */
    .AddNewtonsoftJson()
    .ConfigureApiBehaviorOptions(options =>
    {
        // TODO:NG-56 - configure validation errors to return in standard response format - eg https://stackoverflow.com/a/64784861
        // options.InvalidModelStateResponseFactory = context => { }
    });

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
services.AddEndpointsApiExplorer();
services.AddSwaggerGen();
services.AddSwaggerGenNewtonsoftSupport();

services.AddCors(options =>
{
    options.AddDefaultPolicy(corsPolicyBuilder =>
    {
        corsPolicyBuilder.AllowAnyOrigin().AllowAnyMethod();
    });
});

host.ConfigureLogging((hostBuilderContext, loggingBuilder) =>
{
    if (hostBuilderContext.HostingEnvironment.IsDevelopment())
    {
        loggingBuilder.AddSimpleConsole(options =>
        {
            options.IncludeScopes = true;
            options.SingleLine = true;
            options.TimestampFormat = "hh:mm:ss ";
        });
    }
    else
    {
        loggingBuilder.AddJsonConsole(options =>
        {
            options.IncludeScopes = true;
            options.TimestampFormat = "hh:mm:ss ";
        });
    }
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();
app.UseCors();

await EnsureCanConnectToDatabase(app);
await LoadNetworkConfigurationFromDb(app);

await app.RunAsync();

/* Methods */

async Task EnsureCanConnectToDatabase(WebApplication app1)
{
    var maxWaitForDbMs = app1.Configuration.GetValue("MaxWaitForDbOnStartupMs", 0);
    await ConnectionHelpers.TryWaitForExistingDb<GatewayReadOnlyDbContext>(app1.Services, maxWaitForDbMs);
}

async Task LoadNetworkConfigurationFromDb(WebApplication webApplication)
{
    using (var scope = webApplication.Services.CreateScope())
    {
        await scope.ServiceProvider.GetRequiredService<INetworkConfigurationProvider>()
            .LoadNetworkConfigurationFromDatabase(
                scope.ServiceProvider.GetRequiredService<GatewayReadOnlyDbContext>(),
                CancellationToken.None
            );
    }
}

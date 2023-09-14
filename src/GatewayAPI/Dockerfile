# This dockerfile should be build with the context at the root of the repo, eg, from the repo root:
# docker build -f src/GatewayAPI/Dockerfile .

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443
EXPOSE 1235

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore "src/GatewayAPI/GatewayAPI.csproj"
RUN dotnet build "src/GatewayAPI/GatewayAPI.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "src/GatewayAPI/GatewayAPI.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "GatewayAPI.dll"]

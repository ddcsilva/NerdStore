#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:3.1 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:3.1 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["src/Services/NSE.Pedido.API/NSE.Pedido.API.csproj", "src/Services/NSE.Pedido.API/"]
RUN dotnet restore "./src/Services/NSE.Pedido.API/NSE.Pedido.API.csproj"
COPY . .
WORKDIR "/src/src/Services/NSE.Pedido.API"
RUN dotnet build "./NSE.Pedido.API.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./NSE.Pedido.API.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "NSE.Pedido.API.dll"]
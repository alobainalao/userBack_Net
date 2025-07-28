# Etapa 1: build
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

COPY . .
RUN dotnet restore
RUN dotnet publish -c Release -o /app/publish

# Etapa 2: runtime
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build /app/publish .

# Escucha el puerto asignado por Render
ENV ASPNETCORE_URLS=http://+:$PORT

ENTRYPOINT ["dotnet", "MyJwtApi.dll"]

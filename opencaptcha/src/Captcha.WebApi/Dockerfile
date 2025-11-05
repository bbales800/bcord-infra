# ================================
# 🧩 Stage 1 — Base Runtime Image
# ================================
FROM mcr.microsoft.com/dotnet/aspnet:9.0-noble AS base
WORKDIR /app
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
# ✅ Lightweight .NET-native healthcheck
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=5 \
  CMD dotnet --info > /dev/null || exit 1
# ================================
# 🏗️ Stage 2 — Build Environment
# ================================
FROM mcr.microsoft.com/dotnet/sdk:9.0-noble AS build
WORKDIR /src
ARG BUILD_CONFIGURATION=Release

# Copy project files first (better layer caching)
COPY ["src/Captcha.WebApi/Captcha.WebApi.csproj", "src/Captcha.WebApi/"]
COPY ["src/Captcha.Core/Captcha.Core.csproj", "src/Captcha.Core/"]
RUN dotnet restore "./src/Captcha.WebApi/Captcha.WebApi.csproj"

# Copy everything else and build
COPY . .
WORKDIR "/src/src/Captcha.WebApi"
RUN dotnet build "./Captcha.WebApi.csproj" -c $BUILD_CONFIGURATION -o /app/build

# ================================
# 🚀 Stage 3 — Publish / Optimize
# ================================
FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./Captcha.WebApi.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

# ================================
# 🧩 Stage 4 — Final Runtime Image
# ================================
FROM base AS final
WORKDIR /app

# ✅ Add wget for Docker healthcheck support
RUN apt-get update && apt-get install -y --no-install-recommends wget && rm -rf /var/lib/apt/lists/*

COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Captcha.WebApi.dll"]



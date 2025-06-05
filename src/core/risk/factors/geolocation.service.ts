import { Injectable } from "@tsed/di"
import { riskConfig } from "../../../config/risk.config"
import { logger } from "../../../infrastructure/logging/logger"
import type { CacheService } from "../../cache/cache.service"
import type { HttpClient } from "../../../infrastructure/http/http-client"
import type { GeolocationData } from "../risk-types"
import type { UserLoginHistoryRepository } from "../../../data/repositories/user-login-history.repository"
import type { EventEmitter } from "../../../infrastructure/events/event-emitter"
import { RiskEvent } from "../risk-events"

@Injectable()
export class GeolocationService {
  private readonly CACHE_PREFIX = "geolocation:"
  private readonly CACHE_TTL = riskConfig.geolocation.cacheTime
  private readonly EARTH_RADIUS_KM = 6371 // Earth radius in kilometers

  constructor(
    private cacheService: CacheService,
    private httpClient: HttpClient,
    private userLoginHistoryRepository: UserLoginHistoryRepository,
    private eventEmitter: EventEmitter,
  ) {}

  /**
   * Assess risk based on geolocation
   * @param userId User ID (optional)
   * @param ipAddress IP address
   * @returns Risk score (0-100)
   */
  async assessRisk(userId: string | null, ipAddress: string): Promise<number> {
    try {
      if (!ipAddress) {
        logger.debug("No IP address provided for geolocation risk assessment")
        return 0
      }

      // Get geolocation data
      const geoData = await this.getGeolocationData(ipAddress)
      if (!geoData) {
        return 0 // No data, no risk
      }

      // Initialize risk score
      let riskScore = 0
      const riskFactors = riskConfig.geolocation.riskFactors

      // Check for VPN, Tor, or proxy
      if (geoData.vpn) {
        riskScore = Math.max(riskScore, riskFactors.vpnDetected)
      }

      if (geoData.tor) {
        riskScore = Math.max(riskScore, riskFactors.torDetected)
      }

      if (geoData.proxy) {
        riskScore = Math.max(riskScore, riskFactors.proxyDetected)
      }

      // Check for high-risk country
      if (
        riskConfig.geolocation.highRiskCountries.length > 0 &&
        geoData.countryCode &&
        riskConfig.geolocation.highRiskCountries.includes(geoData.countryCode)
      ) {
        riskScore = Math.max(riskScore, riskFactors.highRiskCountry)
      }

      // For existing users, check for location changes and impossible travel
      if (userId) {
        // Get user's login history
        const loginHistory = await this.userLoginHistoryRepository.findRecentByUserId(userId, 10)

        if (loginHistory.length > 0) {
          // Check for country change
          const lastLogin = loginHistory[0]
          if (lastLogin.countryCode && geoData.countryCode && lastLogin.countryCode !== geoData.countryCode) {
            riskScore = Math.max(riskScore, riskFactors.countryChange)

            // Emit location change event
            this.eventEmitter.emit(RiskEvent.LOCATION_CHANGE_DETECTED, {
              userId,
              ipAddress,
              previousCountry: lastLogin.countryCode,
              currentCountry: geoData.countryCode,
              timestamp: new Date(),
            })
          }

          // Check for impossible travel
          if (
            lastLogin.latitude &&
            lastLogin.longitude &&
            lastLogin.timestamp &&
            geoData.latitude &&
            geoData.longitude
          ) {
            const distance = this.calculateDistance(
              lastLogin.latitude,
              lastLogin.longitude,
              geoData.latitude,
              geoData.longitude,
            )

            const timeDiff = (Date.now() - lastLogin.timestamp.getTime()) / 1000 / 60 / 60 // hours
            const speedKmh = distance / timeDiff

            // If speed is greater than 1000 km/h (faster than commercial flight)
            // and distance is significant (> 500 km)
            if (speedKmh > 1000 && distance > 500) {
              riskScore = Math.max(riskScore, riskFactors.impossibleTravel)

              // Emit impossible travel event
              this.eventEmitter.emit(RiskEvent.IMPOSSIBLE_TRAVEL_DETECTED, {
                userId,
                ipAddress,
                distance,
                timeElapsed: timeDiff,
                speed: speedKmh,
                from: {
                  latitude: lastLogin.latitude,
                  longitude: lastLogin.longitude,
                  country: lastLogin.countryCode,
                  timestamp: lastLogin.timestamp,
                },
                to: {
                  latitude: geoData.latitude,
                  longitude: geoData.longitude,
                  country: geoData.countryCode,
                  timestamp: new Date(),
                },
              })
            }
          }
        }
      }

      logger.debug("Geolocation risk assessment completed", {
        ipAddress,
        country: geoData.country,
        riskScore,
      })

      return riskScore
    } catch (error) {
      logger.error("Error assessing geolocation risk", { error, ipAddress })
      return 0 // Default to no risk on error
    }
  }

  /**
   * Get geolocation data for an IP address
   * @param ipAddress IP address
   * @returns Geolocation data
   */
  async getGeolocationData(ipAddress: string): Promise<GeolocationData | null> {
    try {
      if (!ipAddress) {
        logger.debug("No IP address provided for geolocation data")
        return null
      }

      // Check cache first
      const cacheKey = `${this.CACHE_PREFIX}${ipAddress}`
      const cachedData = await this.cacheService.get<GeolocationData>(cacheKey)

      if (cachedData) {
        return cachedData
      }

      // Get data from configured providers
      let geoData: GeolocationData | null = null
      const providers = riskConfig.geolocation.providers

      // Try providers in order until we get data
      if (providers.includes("local")) {
        geoData = await this.getLocalGeolocationData(ipAddress)
      }

      if (!geoData && providers.includes("ipinfo")) {
        geoData = await this.getIpInfoGeolocationData(ipAddress)
      }

      if (!geoData && providers.includes("maxmind")) {
        geoData = await this.getMaxMindGeolocationData(ipAddress)
      }

      if (!geoData && providers.includes("ipgeolocation")) {
        geoData = await this.getIpGeolocationData(ipAddress)
      }

      // Cache the result if we got data
      if (geoData) {
        await this.cacheService.set(cacheKey, geoData, this.CACHE_TTL)
      }

      return geoData
    } catch (error) {
      logger.error("Error getting geolocation data", { error, ipAddress })
      return null
    }
  }

  /**
   * Get geolocation data from local database
   * @param ipAddress IP address
   * @returns Geolocation data
   */
  private async getLocalGeolocationData(ipAddress: string): Promise<GeolocationData | null> {
    try {
      // In a real implementation, this would query a local database or file
      // For now, we'll use a simple implementation that returns mock data

      // For localhost and private IPs
      if (
        ipAddress === "127.0.0.1" ||
        ipAddress === "::1" ||
        ipAddress.startsWith("10.") ||
        ipAddress.startsWith("192.168.") ||
        ipAddress.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./)
      ) {
        return {
          ip: ipAddress,
          country: "Local",
          countryCode: "LO",
          region: "Local",
          regionCode: "LO",
          city: "Local",
          postalCode: "00000",
          latitude: 0,
          longitude: 0,
          timezone: "UTC",
          isp: "Local",
          org: "Local",
          asn: "AS0",
          proxy: false,
          vpn: false,
          tor: false,
          hosting: false,
          risk: 0,
        }
      }

      // For demonstration purposes, generate mock data based on IP
      // In a real implementation, this would use a GeoIP database
      const ipParts = ipAddress.split(".")
      if (ipParts.length === 4) {
        const firstOctet = Number.parseInt(ipParts[0], 10)
        const secondOctet = Number.parseInt(ipParts[1], 10)

        // Generate deterministic but "random" values based on IP
        const latBase = (firstOctet % 180) - 90 + (secondOctet / 255) * 10
        const lonBase = (firstOctet % 360) - 180 + (secondOctet / 255) * 10

        // Determine country based on IP range (for demonstration)
        let country = "United States"
        let countryCode = "US"

        if (firstOctet < 100) {
          country = "United States"
          countryCode = "US"
        } else if (firstOctet < 150) {
          country = "United Kingdom"
          countryCode = "GB"
        } else if (firstOctet < 200) {
          country = "Germany"
          countryCode = "DE"
        } else {
          country = "Japan"
          countryCode = "JP"
        }

        // Determine if it's a proxy/VPN/Tor (for demonstration)
        const isProxy = secondOctet > 200
        const isVpn = secondOctet > 220
        const isTor = secondOctet > 240

        return {
          ip: ipAddress,
          country,
          countryCode,
          region: "Region",
          regionCode: "RG",
          city: "City",
          postalCode: "12345",
          latitude: latBase,
          longitude: lonBase,
          timezone: "UTC",
          isp: "ISP",
          org: "Organization",
          asn: `AS${firstOctet}${secondOctet}`,
          proxy: isProxy,
          vpn: isVpn,
          tor: isTor,
          hosting: false,
          risk: isProxy || isVpn || isTor ? 70 : 0,
        }
      }

      return null
    } catch (error) {
      logger.error("Error getting local geolocation data", { error, ipAddress })
      return null
    }
  }

  /**
   * Get geolocation data from IPInfo
   * @param ipAddress IP address
   * @returns Geolocation data
   */
  private async getIpInfoGeolocationData(ipAddress: string): Promise<GeolocationData | null> {
    try {
      // In a real implementation, this would call the IPInfo API
      // For now, we'll simulate a response

      // Simulate API call delay
      await new Promise((resolve) => setTimeout(resolve, 150))

      // For demonstration purposes, return null to simulate API failure
      // This will cause the system to try the next provider
      return null
    } catch (error) {
      logger.error("Error getting IPInfo geolocation data", { error, ipAddress })
      return null
    }
  }

  /**
   * Get geolocation data from MaxMind
   * @param ipAddress IP address
   * @returns Geolocation data
   */
  private async getMaxMindGeolocationData(ipAddress: string): Promise<GeolocationData | null> {
    try {
      // In a real implementation, this would call the MaxMind API or use their database
      // For now, we'll simulate a response

      // Simulate API call delay
      await new Promise((resolve) => setTimeout(resolve, 100))

      // For demonstration purposes, return null to simulate API failure
      // This will cause the system to try the next provider
      return null
    } catch (error) {
      logger.error("Error getting MaxMind geolocation data", { error, ipAddress })
      return null
    }
  }

  /**
   * Get geolocation data from IPGeolocation
   * @param ipAddress IP address
   * @returns Geolocation data
   */
  private async getIpGeolocationData(ipAddress: string): Promise<GeolocationData | null> {
    try {
      // In a real implementation, this would call the IPGeolocation API
      // For now, we'll simulate a response

      // Simulate API call delay
      await new Promise((resolve) => setTimeout(resolve, 120))

      // For demonstration purposes, return null to simulate API failure
      return null
    } catch (error) {
      logger.error("Error getting IPGeolocation data", { error, ipAddress })
      return null
    }
  }

  /**
   * Calculate distance between two points using the Haversine formula
   * @param lat1 Latitude of point 1
   * @param lon1 Longitude of point 1
   * @param lat2 Latitude of point 2
   * @param lon2 Longitude of point 2
   * @returns Distance in kilometers
   */
  private calculateDistance(lat1: number, lon1: number, lat2: number, lon2: number): number {
    const dLat = this.toRadians(lat2 - lat1)
    const dLon = this.toRadians(lon2 - lon1)

    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(this.toRadians(lat1)) * Math.cos(this.toRadians(lat2)) * Math.sin(dLon / 2) * Math.sin(dLon / 2)

    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a))
    const distance = this.EARTH_RADIUS_KM * c

    return distance
  }

  /**
   * Convert degrees to radians
   * @param degrees Angle in degrees
   * @returns Angle in radians
   */
  private toRadians(degrees: number): number {
    return degrees * (Math.PI / 180)
  }
}

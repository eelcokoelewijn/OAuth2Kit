import Foundation

// MARK: refresh token request

public struct RefreshTokenRequest {
    public let endpoint: URL
    public let grantType: OAuth2GrantType
    public let refreshToken: String
    public let scope: String?
}

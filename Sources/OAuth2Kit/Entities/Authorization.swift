import Foundation

// MARK: oauth response types

public enum OAuth2ResponseType: String {
    case code
}

// MARK: authorization request & result

public struct AuthorizationRequest {
    public let endpoint: URL
    public let responseType: OAuth2ResponseType
    public let client: OAuthClient
    public let redirectURI: URL
    public let scope: String
    public let state: String
}

public struct AuthorizationResult {
    public let code: String
    public let state: String
}

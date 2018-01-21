import Foundation

// MARK: grant types

public enum OAuth2GrantType: String {
    case authorizationCode = "authorization_code"
    case refreshToken = "refresh_token"
}

// MARK: token exchange request & result

public struct TokenExchangeRequest {
    public let endpoint: URL
    public let code: String
    public let client: Client
    public let redirectURI: URL
    public let grantType: OAuth2GrantType
}

//{
//"access_token":"2YotnFZFEjr1zCsicMWpAA",
//"token_type":"example",
//"expires_in":3600,
//"refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
//"example_parameter":"example_value"
//}
public struct TokenExchangeResult: Codable {
    public let accessToken: String
    public let tokenType: String
    public let expiresIn: Date?
    public let refreshToken: String?
    public let exampleParameter: String?
    public let scope: String?
    
    //add mapping for properties
}

import Foundation

// MARK: grant types

public enum OAuth2GrantType: String {
    case authorizationCode = "authorization_code"
    case refreshToken = "refresh_token"
}

// MARK: oauth response types

public enum OAuth2ResponseType: String {
    case code
}

// MARK: Result & Error

//{
//    "error":"invalid_request",
//    "error_description":"",
//    "error_uri":""
//}
public struct OAuth2Error: Error, Codable {
    let error: String
    let state: String?
    let errorDescription: String?
    let errorURI: URL?
    // add mapping for properties!
}

public enum OAuth2Result<ResultType> {
    case success(ResultType)
    case failed(OAuth2Error)
}

// MARK: Client entity

public struct Client {
    public let clientId: String
    public let clientSecret: String?
}

// MARK: authorization request & result

public struct AuthorizationRequest {
    public let endpoint: URL
    public let responseType: OAuth2ResponseType
    public let client: Client
    public let redirectURI: URL
    public let scope: String
    public let state: String
}

public struct AuthorizationResult {
    public let code: String
    public let state: String
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

// MARK: refresh token request

public struct RefreshTokenRequest {
    public let endpoint: URL
    public let grantType: OAuth2GrantType
    public let refreshToken: String
    public let scope: String?
}

// MARK: OAuth2NetworkService interface

public enum OAuth2NetworkServiceError: Error {
    case failed
}

public enum OAuth2NetworkServiceResult<ResultType> {
    case success(ResultType)
    case failed(OAuth2NetworkServiceError)
}

public protocol OAuth2NetworkService {
    func post(withEndpoint endpoint: URL,
             withParameters params: [String: String?],
             completion: @escaping (OAuth2NetworkServiceResult<Data>) -> Void)
    func createURLRequest(withURL url: URL, method: String, parameters: [String: String]) -> URLRequest
    func getQueryParameters(fromURL url: URL) -> [String: String]
}

protocol UsesOAuth2NetworkService {
    var networkService: OAuth2NetworkService { get }
}

// MARK: OAuth2Kit interface + implementation

public protocol OAuth2Kit {
    func authorizeRequest(_ request: AuthorizationRequest) -> URLRequest
    func handleAuthorizeResponse(_ response: HTTPURLResponse) -> OAuth2Result<AuthorizationResult>
    func tokenExchange(request: TokenExchangeRequest, completion: @escaping (OAuth2Result<TokenExchangeResult>) -> Void)
    func refreshToken(request: RefreshTokenRequest, completion: @escaping (OAuth2Result<TokenExchangeResult>) -> Void)
}

public protocol UsesOAuth2Kit {
    var oAuth2Kit: OAuth2Kit { get }
}

public class MixinOAuth2Kit: OAuth2Kit, UsesOAuth2NetworkService {
    internal let networkService: OAuth2NetworkService
    
    init(networkService: OAuth2NetworkService) {
        self.networkService = networkService
    }
    
    public func authorizeRequest(_ request: AuthorizationRequest) -> URLRequest {
        //if available add PKCE
        //code_challenge=XXXXXXX - This is a base64-encoded version of the sha256 hash of the code verifier string
        //code_challenge_method=S256 - Indicates the hashing method used to compute the challenge, in this case, sha256.
        let params: [String: String] = ["client_id": request.client.clientId,
                                        "response_type": request.responseType.rawValue,
                                        "redirect_uri": request.redirectURI.absoluteString,
                                        "scope": request.scope,
                                        "state": request.state]
        return networkService.createURLRequest(withURL: request.endpoint,
                                               method: "GET",
                                               parameters: params)
    }
    
    public func handleAuthorizeResponse(_ response: HTTPURLResponse) -> OAuth2Result<AuthorizationResult> {
        //validate state against provided state in request
        //PKCE code_verifier check against challenge
        guard let url: URL = response.url else {
            return OAuth2Result.failed(OAuth2Error(error: "no response url found for response",
                                                   state: nil,
                                                   errorDescription: nil,
                                                   errorURI: nil))
        }
        let params: [String: String] = networkService.getQueryParameters(fromURL: url)
        let authResult: AuthorizationResult = AuthorizationResult(code: params["code"]!,
                                                                  state: params["state"]!)
        return OAuth2Result.success(authResult)
    }
    
    public func tokenExchange(request: TokenExchangeRequest,
                              completion: @escaping (OAuth2Result<TokenExchangeResult>) -> Void) {
        let params: [String: String?] = ["grant_type": request.grantType.rawValue,
                                        "code": request.code,
                                        "redirect_uri": request.redirectURI.absoluteString,
                                        "client_id": request.client.clientId,
                                        "client_secret": request.client.clientSecret]
        networkService.post(withEndpoint: request.endpoint,
                            withParameters: params) { [unowned self] (result: OAuth2NetworkServiceResult<Data>) in
                                    completion(self.handleTokenExchangeResponse(result))
        }
    }
    
    public func refreshToken(request: RefreshTokenRequest,
                             completion: @escaping (OAuth2Result<TokenExchangeResult>) -> Void) {
        let params: [String: String?] = ["grant_type": request.grantType.rawValue,
                                         "refresh_token": request.refreshToken,
                                         "scope": request.scope]
        networkService.post(withEndpoint: request.endpoint,
                            withParameters: params) { [unowned self] (result: OAuth2NetworkServiceResult<Data>) in
                                completion(self.handleTokenExchangeResponse(result))
        }
    }
    
    private func handleTokenExchangeResponse(_ response: OAuth2NetworkServiceResult<Data>) -> OAuth2Result<TokenExchangeResult> {
        guard case OAuth2NetworkServiceResult.failed = response else {
            return OAuth2Result.failed(OAuth2Error(error: "request failed",
                                                       state: nil,
                                                       errorDescription: nil,
                                                       errorURI: nil))
        }
        if case let OAuth2NetworkServiceResult.success(data) = response {
            do {
                let token: TokenExchangeResult = try JSONDecoder().decode(TokenExchangeResult.self, from: data)
                return OAuth2Result.success(token)
            } catch {
                return OAuth2Result.failed(OAuth2Error(error: "parse json result failed",
                                                           state: nil,
                                                           errorDescription: nil,
                                                           errorURI: nil))
            }
        }
        return OAuth2Result.failed(OAuth2Error(error: "handling of token exchange response failed",
                                               state: nil,
                                               errorDescription: nil,
                                               errorURI: nil))
    }
}



import Foundation

public enum OAuth2Result<ResultType> {
    case success(ResultType)
    case failed(OAuth2Error)
}

// MARK: Client entity

public struct Client {
    public let clientId: String
    public let clientSecret: String?
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



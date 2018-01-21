import Foundation

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

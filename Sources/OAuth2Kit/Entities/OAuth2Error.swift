import Foundation
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

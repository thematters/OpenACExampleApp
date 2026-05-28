//
//  PersonhoodHandoff.swift
//  OpenACExampleApp
//

import Foundation

struct PersonhoodProofInput: Equatable {
  let appId: String
  let challenge: String
  let challengeExpiresAt: String?
  let cert: String
  let signedResponse: String
}

struct PersonhoodHelperHandoff: Equatable {
  let version: Int
  let source: String?
  let createdAt: String?
  let proofInput: PersonhoodProofInput
  let linkVerifyURL: URL
  let certChainType: String?
  let certChainProvingKeyURL: URL?
  let userSigProvingKeyURL: URL?
  let smtSnapshotURL: URL?
  let returnURL: URL?
}

enum PersonhoodHandoffError: LocalizedError {
  case unsupportedURL
  case missingPayload
  case invalidPayloadEncoding
  case invalidPayloadJSON
  case unsupportedVersion(Int)
  case missingRequiredField(String)
  case invalidURL(String)

  var errorDescription: String? {
    switch self {
    case .unsupportedURL:
      return "Unsupported handoff URL"
    case .missingPayload:
      return "Missing handoff payload"
    case .invalidPayloadEncoding:
      return "Invalid handoff payload encoding"
    case .invalidPayloadJSON:
      return "Invalid handoff payload JSON"
    case .unsupportedVersion(let version):
      return "Unsupported handoff version: \(version)"
    case .missingRequiredField(let field):
      return "Missing required handoff field: \(field)"
    case .invalidURL(let field):
      return "Invalid handoff URL field: \(field)"
    }
  }
}

extension PersonhoodHelperHandoff {
  static func decode(from url: URL) throws -> PersonhoodHelperHandoff {
    guard url.scheme == "openac", url.host == "prove" else {
      throw PersonhoodHandoffError.unsupportedURL
    }
    guard
      let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
      let encoded = components.queryItems?.first(where: { $0.name == "payload" })?.value,
      !encoded.isEmpty
    else {
      throw PersonhoodHandoffError.missingPayload
    }
    guard let data = Data(base64URLEncoded: encoded) else {
      throw PersonhoodHandoffError.invalidPayloadEncoding
    }
    guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
      throw PersonhoodHandoffError.invalidPayloadJSON
    }
    return try decode(from: json)
  }

  private static func decode(from json: [String: Any]) throws -> PersonhoodHelperHandoff {
    let version = json["version"] as? Int ?? 1
    guard version == 1 else { throw PersonhoodHandoffError.unsupportedVersion(version) }

    guard let proofInput = json["proofInput"] as? [String: Any] else {
      throw PersonhoodHandoffError.missingRequiredField("proofInput")
    }
    guard let appId = proofInput["appId"] as? String, !appId.isEmpty else {
      throw PersonhoodHandoffError.missingRequiredField("proofInput.appId")
    }
    guard let challenge = proofInput["challenge"] as? String, !challenge.isEmpty else {
      throw PersonhoodHandoffError.missingRequiredField("proofInput.challenge")
    }
    guard let cert = proofInput["cert"] as? String, !cert.isEmpty else {
      throw PersonhoodHandoffError.missingRequiredField("proofInput.cert")
    }
    guard let signedResponse = proofInput["signedResponse"] as? String, !signedResponse.isEmpty
    else {
      throw PersonhoodHandoffError.missingRequiredField("proofInput.signedResponse")
    }
    guard let linkVerifyString = json["linkVerifyUrl"] as? String,
      let linkVerifyURL = URL(string: linkVerifyString),
      ["http", "https"].contains(linkVerifyURL.scheme?.lowercased())
    else {
      throw PersonhoodHandoffError.invalidURL("linkVerifyUrl")
    }

    return PersonhoodHelperHandoff(
      version: version,
      source: json["source"] as? String,
      createdAt: json["createdAt"] as? String,
      proofInput: PersonhoodProofInput(
        appId: appId,
        challenge: challenge,
        challengeExpiresAt: proofInput["challengeExpiresAt"] as? String,
        cert: cert,
        signedResponse: signedResponse
      ),
      linkVerifyURL: linkVerifyURL,
      certChainType: json["certChainType"] as? String,
      certChainProvingKeyURL: urlField(json, "certChainProvingKeyUrl"),
      userSigProvingKeyURL: urlField(json, "userSigProvingKeyUrl"),
      smtSnapshotURL: urlField(json, "smtSnapshotUrl"),
      returnURL: urlField(json, "returnUrl")
    )
  }

  private static func urlField(_ json: [String: Any], _ key: String) -> URL? {
    guard let raw = json[key] as? String, !raw.isEmpty else { return nil }
    return URL(string: raw)
  }
}

private extension Data {
  init?(base64URLEncoded string: String) {
    var base64 = string
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let padding = (4 - base64.count % 4) % 4
    base64.append(String(repeating: "=", count: padding))
    self.init(base64Encoded: base64)
  }
}

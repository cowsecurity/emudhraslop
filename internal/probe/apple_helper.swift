import Foundation
import Security

struct Input: Decodable {
    let id: String
    let hostname: String
    let certificates: [String]
}
struct Check: Encodable {
    let id: String
    let accepted: Bool
    let error: Int
}
struct Output: Encodable {
    let version: String
    let checks: [Check]
}

// Public certificates arrive over stdin. No key material, app arguments,
// environment variables, remote URLs or trust settings are read or modified.
let bytes = FileHandle.standardInput.readData(ofLength: 1_048_577)
guard bytes.count <= 1_048_576,
      let inputs = try? JSONDecoder().decode([Input].self, from: bytes),
      inputs.count <= 64 else { exit(2) }
var checks: [Check] = []
for input in inputs {
    guard input.certificates.count >= 2, input.certificates.count <= 8,
          !input.hostname.isEmpty else { exit(2) }
    var certificates: [SecCertificate] = []
    for encoded in input.certificates {
        guard let data = Data(base64Encoded: encoded),
              let certificate = SecCertificateCreateWithData(nil, data as CFData)
        else { exit(2) }
        certificates.append(certificate)
    }
    let policy = SecPolicyCreateSSL(true, input.hostname as CFString)
    var trust: SecTrust?
    guard SecTrustCreateWithCertificates(certificates as CFArray, policy, &trust) == errSecSuccess,
          let trust = trust,
          SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess else { exit(2) }
    var error: CFError?
    let accepted = SecTrustEvaluateWithError(trust, &error)
    checks.append(Check(id: input.id, accepted: accepted,
                        error: error.map { CFErrorGetCode($0) } ?? 0))
}
let version = ProcessInfo.processInfo.operatingSystemVersion
let result = Output(version: "macOS \(version.majorVersion).\(version.minorVersion).\(version.patchVersion)", checks: checks)
guard let output = try? JSONEncoder().encode(result) else { exit(2) }
FileHandle.standardOutput.write(output)

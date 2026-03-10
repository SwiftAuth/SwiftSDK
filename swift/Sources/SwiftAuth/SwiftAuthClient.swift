import Foundation
#if canImport(CommonCrypto)
import CommonCrypto
#endif
#if canImport(CryptoKit)
import CryptoKit
#endif
import Compression

// MARK: - Error

public struct SwiftAuthError: Error, LocalizedError {
    public let code: String
    public let message: String

    public var errorDescription: String? { "[\(code)] \(message)" }
}

// MARK: - Models

public struct AppInfo {
    public let name: String
    public let version: String
    public let antiDebug: Bool
    public let antiVM: Bool
    public let lockHwid: Bool
    public let lockIp: Bool
    public let lockPcName: Bool
}

public struct UserData {
    public let key: String
    public let username: String
    public let email: String
    public let level: Int
    public let expiresAt: String?
    public let metadata: Any?
}

public struct Variable {
    public let key: String
    public let value: String
    public let type: String
}

public struct UserVariable {
    public let key: String
    public let value: String
}

// MARK: - Client

public class SwiftAuthClient {
    private let baseURL: String
    private let secret: String
    private let version: String
    private let hwid: String
    private let session: URLSession

    private var sessionToken: String?
    private var nonce: String?

    public private(set) var app: AppInfo?
    public private(set) var user: UserData?

    public var isInitialized: Bool { sessionToken != nil }
    public var currentSessionToken: String? { sessionToken }

    public init(baseURL: String, appSecret: String, appVersion: String = "1.0.0", hwid: String? = nil) {
        self.baseURL = baseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        self.secret = appSecret
        self.version = appVersion
        self.hwid = hwid ?? SwiftAuthClient.defaultHwid()
        self.session = URLSession(configuration: .default)
    }

    // MARK: - Initialization

    public func initialize() throws -> [String: Any] {
        let data = try post(path: "/api/client/init", payload: [
            "secret": secret,
            "version": version,
            "hwid": hwid,
        ])
        sessionToken = data["sessionToken"] as? String ?? ""
        app = AppInfo(
            name: data["appName"] as? String ?? "",
            version: data["appVersion"] as? String ?? "",
            antiDebug: data["antiDebug"] as? Bool ?? false,
            antiVM: data["antiVM"] as? Bool ?? false,
            lockHwid: data["lockHwid"] as? Bool ?? false,
            lockIp: data["lockIp"] as? Bool ?? false,
            lockPcName: data["lockPcName"] as? Bool ?? false
        )
        return data
    }

    private func fetchNonce() throws {
        let data = try post(path: "/api/client/nonce", payload: ["sessionToken": sessionToken!])
        nonce = data["nonce"] as? String ?? ""
    }

    // MARK: - Authentication

    public func login(username: String, password: String, licenseKey: String = "", pcName: String = "") throws -> [String: Any] {
        try requireInit()
        try fetchNonce()
        let data = try postWithNonce(path: "/api/client/login", payload: [
            "sessionToken": sessionToken!,
            "username": username,
            "password": password,
            "licenseKey": licenseKey,
            "hwid": hwid,
            "pcName": pcName,
        ])
        user = Self.parseUser(data)
        return data
    }

    public func register(username: String, password: String, email: String = "", displayName: String = "", licenseKey: String = "", pcName: String = "") throws -> [String: Any] {
        try requireInit()
        try fetchNonce()
        let data = try postWithNonce(path: "/api/client/register", payload: [
            "sessionToken": sessionToken!,
            "username": username,
            "password": password,
            "email": email,
            "displayName": displayName,
            "licenseKey": licenseKey,
            "hwid": hwid,
            "pcName": pcName,
        ])
        user = Self.parseUser(data)
        return data
    }

    public func licenseLogin(licenseKey: String, pcName: String = "") throws -> [String: Any] {
        try requireInit()
        try fetchNonce()
        let data = try postWithNonce(path: "/api/client/license", payload: [
            "sessionToken": sessionToken!,
            "licenseKey": licenseKey,
            "hwid": hwid,
            "pcName": pcName,
        ])
        user = Self.parseUser(data)
        return data
    }

    // MARK: - Token Validation

    public func validateToken(_ token: String) throws -> [String: Any] {
        try requireInit()
        return try post(path: "/api/client/token", payload: ["sessionToken": sessionToken!, "token": token])
    }

    // MARK: - License Activation

    public func activate(licenseKey: String) throws -> [String: Any] {
        try requireInit()
        try fetchNonce()
        return try postWithNonce(path: "/api/client/activate", payload: [
            "sessionToken": sessionToken!,
            "licenseKey": licenseKey,
        ])
    }

    // MARK: - Variables

    public func getVariable(key: String) throws -> Variable {
        try requireInit()
        let data = try post(path: "/api/client/variable", payload: ["sessionToken": sessionToken!, "key": key])
        return Variable(key: data["key"] as? String ?? "", value: data["value"] as? String ?? "", type: data["type"] as? String ?? "STRING")
    }

    public func getAllVariables() throws -> [Variable] {
        try requireInit()
        let result = try postRaw(path: "/api/client/variables", payload: ["sessionToken": sessionToken!])
        guard let list = result as? [[String: Any]] else { return [] }
        return list.map { Variable(key: $0["key"] as? String ?? "", value: $0["value"] as? String ?? "", type: $0["type"] as? String ?? "STRING") }
    }

    // MARK: - User Variables

    public func getUserVariable(key: String) throws -> UserVariable {
        try requireInit()
        let data = try post(path: "/api/client/user-variable", payload: ["sessionToken": sessionToken!, "key": key])
        return UserVariable(key: data["key"] as? String ?? "", value: data["value"] as? String ?? "")
    }

    public func getAllUserVariables() throws -> [UserVariable] {
        try requireInit()
        let result = try postRaw(path: "/api/client/user-variables", payload: ["sessionToken": sessionToken!])
        guard let list = result as? [[String: Any]] else { return [] }
        return list.map { UserVariable(key: $0["key"] as? String ?? "", value: $0["value"] as? String ?? "") }
    }

    public func setUserVariable(key: String, value: String) throws -> UserVariable {
        try requireInit()
        let data = try post(path: "/api/client/set-user-variable", payload: [
            "sessionToken": sessionToken!,
            "key": key,
            "value": value,
        ])
        return UserVariable(key: data["key"] as? String ?? "", value: data["value"] as? String ?? "")
    }

    public func deleteUserVariable(key: String) throws {
        try requireInit()
        _ = try post(path: "/api/client/delete-user-variable", payload: ["sessionToken": sessionToken!, "key": key])
    }

    // MARK: - Files

    public func downloadFile(name: String) throws -> Data {
        try requireInit()
        let payload: [String: Any] = ["sessionToken": sessionToken!, "name": name]
        let jsonData = try JSONSerialization.data(withJSONObject: payload)
        var request = URLRequest(url: URL(string: "\(baseURL)/api/client/file")!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = jsonData

        var responseData: Data?
        var responseObj: HTTPURLResponse?
        var responseError: Error?

        let sem = DispatchSemaphore(value: 0)
        session.dataTask(with: request) { data, response, error in
            responseData = data
            responseObj = response as? HTTPURLResponse
            responseError = error
            sem.signal()
        }.resume()
        sem.wait()

        if let err = responseError { throw SwiftAuthError(code: "NETWORK_ERROR", message: err.localizedDescription) }
        guard var data = responseData else { throw SwiftAuthError(code: "NETWORK_ERROR", message: "No data") }

        if responseObj?.value(forHTTPHeaderField: "x-file-encrypted") == "1",
           let nonceHex = responseObj?.value(forHTTPHeaderField: "x-file-nonce"), !nonceHex.isEmpty {
            data = try Self.decryptFileBytes(data, appSecret: secret, sessionToken: sessionToken!, nonceHex: nonceHex)
        }
        return data
    }

    public func checkUpdate(currentVersion: String, fileName: String = "") throws -> [String: Any] {
        try requireInit()
        return try post(path: "/api/client/check-update", payload: [
            "sessionToken": sessionToken!,
            "currentVersion": currentVersion,
            "fileName": fileName,
        ])
    }

    // MARK: - Session Management

    public func heartbeat() throws -> [String: Any] {
        try requireInit()
        try fetchNonce()
        return try postWithNonce(path: "/api/client/heartbeat", payload: ["sessionToken": sessionToken!])
    }

    public func checkSession() throws -> [String: Any] {
        try requireInit()
        return try post(path: "/api/client/check", payload: ["sessionToken": sessionToken!])
    }

    public func endSession() throws {
        try requireInit()
        _ = try post(path: "/api/client/end", payload: ["sessionToken": sessionToken!])
        sessionToken = nil
        user = nil
    }

    // MARK: - User Info

    public func getUser() throws -> [String: Any] {
        try requireInit()
        return try post(path: "/api/client/user", payload: ["sessionToken": sessionToken!])
    }

    public func changePassword(currentPassword: String, newPassword: String) throws {
        try requireInit()
        _ = try post(path: "/api/client/change-password", payload: [
            "sessionToken": sessionToken!,
            "currentPassword": currentPassword,
            "newPassword": newPassword,
        ])
    }

    public func requestReset() throws {
        try requireInit()
        _ = try post(path: "/api/client/request-reset", payload: ["sessionToken": sessionToken!])
    }

    // MARK: - Client Log

    public func log(message: String, level: String = "INFO") throws {
        try requireInit()
        _ = try post(path: "/api/client/log", payload: [
            "sessionToken": sessionToken!,
            "message": message,
            "level": level,
        ])
    }

    // MARK: - Internal

    private func requireInit() throws {
        guard sessionToken != nil else {
            throw SwiftAuthError(code: "NOT_INITIALIZED", message: "Call initialize() before using other methods.")
        }
    }

    private func post(path: String, payload: [String: Any]) throws -> [String: Any] {
        let result = try request(path: path, payload: payload, extraHeaders: [:])
        if let dict = result as? [String: Any] { return dict }
        return [:]
    }

    private func postRaw(path: String, payload: [String: Any]) throws -> Any {
        return try request(path: path, payload: payload, extraHeaders: [:])
    }

    private func postWithNonce(path: String, payload: [String: Any]) throws -> [String: Any] {
        let result = try request(path: path, payload: payload, extraHeaders: ["X-Nonce": nonce ?? ""])
        if let dict = result as? [String: Any] { return dict }
        return [:]
    }

    private func request(path: String, payload: [String: Any], extraHeaders: [String: String]) throws -> Any {
        let jsonData = try JSONSerialization.data(withJSONObject: payload)
        var urlRequest = URLRequest(url: URL(string: "\(baseURL)\(path)")!)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        urlRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        for (k, v) in extraHeaders {
            urlRequest.setValue(v, forHTTPHeaderField: k)
        }
        urlRequest.httpBody = jsonData

        var responseData: Data?
        var responseError: Error?

        let sem = DispatchSemaphore(value: 0)
        session.dataTask(with: urlRequest) { data, _, error in
            responseData = data
            responseError = error
            sem.signal()
        }.resume()
        sem.wait()

        if let err = responseError {
            throw SwiftAuthError(code: "NETWORK_ERROR", message: err.localizedDescription)
        }
        guard let data = responseData,
              let body = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw SwiftAuthError(code: "PARSE_ERROR", message: "Invalid server response")
        }

        guard body["success"] as? Bool == true else {
            let err = body["error"] as? [String: Any] ?? [:]
            throw SwiftAuthError(
                code: err["code"] as? String ?? "UNKNOWN",
                message: err["message"] as? String ?? "Request failed"
            )
        }

        if let d = body["data"] { return d }
        if let m = body["message"] { return ["message": m] }
        return [String: Any]()
    }

    private static func parseUser(_ data: [String: Any]) -> UserData {
        UserData(
            key: data["key"] as? String ?? "",
            username: data["username"] as? String ?? "",
            email: data["email"] as? String ?? "",
            level: data["level"] as? Int ?? 0,
            expiresAt: data["expiresAt"] as? String,
            metadata: data["metadata"]
        )
    }

    private static func defaultHwid() -> String {
        let host = ProcessInfo.processInfo.hostName
        let user = NSUserName()
        return "\(host)-\(user)"
    }

    // MARK: - Multi-Layer File Decryption

    private static func decryptFileBytes(_ data: Data, appSecret: String, sessionToken: String, nonceHex: String) throws -> Data {
        let nonce = Data(hexString: nonceHex)
        let keys = deriveKeys(appSecret: appSecret, sessionToken: sessionToken, nonce: nonce)
        let aesKey = keys.0
        let shuffleKey = keys.1
        let xorKey = keys.2

        // Layer 4: Rolling XOR
        var buf = [UInt8](data)
        let xorBytes = [UInt8](xorKey)
        for i in 0..<buf.count {
            buf[i] ^= xorBytes[i % xorBytes.count]
        }

        // Layer 3: Fisher-Yates unshuffle
        let n = buf.count
        var rng = SeededRNG(key: [UInt8](shuffleKey))
        var swaps = [Int]()
        for i in stride(from: n - 1, through: 1, by: -1) {
            swaps.append(Int(rng.next() % UInt64(i + 1)))
        }
        for k in stride(from: swaps.count - 1, through: 0, by: -1) {
            let i = n - 1 - k
            let j = swaps[k]
            buf.swapAt(i, j)
        }

        // Layer 2: AES-256-GCM
        let gcmNonce = Data(buf[0..<12])
        let ciphertextAndTag = Data(buf[12...])
        let sealedBox = try AES.GCM.SealedBox(combined: gcmNonce + ciphertextAndTag)
        let symmetricKey = SymmetricKey(data: aesKey)
        let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey)

        // Layer 1: zlib decompress
        let decompressed = try (plaintext as NSData).decompressed(using: .zlib) as Data
        return decompressed
    }

    private static func deriveKeys(appSecret: String, sessionToken: String, nonce: Data) -> (Data, Data, Data) {
        let key = SymmetricKey(data: Data(appSecret.utf8))
        let message = Data("\(sessionToken)|\(nonce.hexString)".utf8)
        let master = Data(HMAC<SHA256>.authenticationCode(for: message, using: key))

        func sub(_ layer: UInt8) -> Data {
            var hasher = SHA256()
            hasher.update(data: master)
            hasher.update(data: Data([layer]))
            return Data(hasher.finalize())
        }

        return (sub(0x01), sub(0x02), sub(0x03))
    }

    private struct SeededRNG {
        var state: UInt64

        init(key: [UInt8]) {
            var s: UInt64 = 0
            if key.count >= 8 {
                s = key[0..<8].withUnsafeBufferPointer { ptr in
                    ptr.baseAddress!.withMemoryRebound(to: UInt64.self, capacity: 1) { $0.pointee }
                }
            }
            for i in 8..<key.count {
                s ^= UInt64(key[i]) << ((UInt64(i % 8)) * 8)
                s = s &* 6364136223846793005 &+ 1442695040888963407
            }
            if s == 0 { s = 0xDEADBEEFCAFE1234 }
            state = s
        }

        mutating func next() -> UInt64 {
            state = state &* 6364136223846793005 &+ 1442695040888963407
            return state
        }
    }
}

// MARK: - Data Extensions

private extension Data {
    init(hexString: String) {
        self.init()
        var hex = hexString
        while hex.count >= 2 {
            let byte = String(hex.prefix(2))
            hex = String(hex.dropFirst(2))
            if let b = UInt8(byte, radix: 16) {
                append(b)
            }
        }
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

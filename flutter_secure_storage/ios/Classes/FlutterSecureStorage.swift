//
//  FlutterSecureStorageManager.swift
//  flutter_secure_storage
//
//  Created by Julian Steenbakker on 22/08/2022.
//

import Foundation
import LocalAuthentication

class FlutterSecureStorage {
    private func parseAccessibleAttr(accessibility: String?) -> CFString {
        guard let accessibility = accessibility else {
            return kSecAttrAccessibleWhenUnlocked
        }
        
        switch accessibility {
        case "passcode":
            return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        case "unlocked":
            return kSecAttrAccessibleWhenUnlocked
        case "unlocked_this_device":
            return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case "first_unlock":
            return kSecAttrAccessibleAfterFirstUnlock
        case "first_unlock_this_device":
            return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        default:
            return kSecAttrAccessibleWhenUnlocked
        }
    }
    
    private func baseQuery(key: String?, groupId: String?, accountName: String?, synchronizable: Bool?, accessibility: String?, returnData: Bool?) -> Dictionary<CFString, Any> {
        var keychainQuery: [CFString: Any] = [
            kSecClass : kSecClassGenericPassword
        ]
        
        if (accessibility != nil) {
            keychainQuery[kSecAttrAccessible] = parseAccessibleAttr(accessibility: accessibility)
        }
        
        if (key != nil) {
            keychainQuery[kSecAttrAccount] = key
        }
        
        if (groupId != nil) {
            keychainQuery[kSecAttrAccessGroup] = groupId
        }
        
        if (accountName != nil) {
            keychainQuery[kSecAttrService] = accountName
        }
        
        if (synchronizable != nil) {
            keychainQuery[kSecAttrSynchronizable] = synchronizable
        }
        
        if (returnData != nil) {
            keychainQuery[kSecReturnData] = returnData
        }
        return keychainQuery
    }
    
    internal func containsKey(key: String, groupId: String?, accountName: String?) -> Result<Bool, OSSecError> {
        // The accessibility parameter has no influence on uniqueness.
        func queryKeychain(synchronizable: Bool) -> OSStatus {
            let keychainQuery = baseQuery(key: key, groupId: groupId, accountName: accountName, synchronizable: synchronizable, accessibility: nil, returnData: false)
            return SecItemCopyMatching(keychainQuery as CFDictionary, nil)
        }
        
        let statusSynchronizable = queryKeychain(synchronizable: true)
        if statusSynchronizable == errSecSuccess {
            return .success(true)
        } else if statusSynchronizable != errSecItemNotFound {
            return .failure(OSSecError(status: statusSynchronizable))
        }
        
        let statusNonSynchronizable = queryKeychain(synchronizable: false)
        switch statusNonSynchronizable {
        case errSecSuccess:
            return .success(true)
        case errSecItemNotFound:
            return .success(false)
        default:
            return .failure(OSSecError(status: statusNonSynchronizable))
        }
    }
    
    internal func readAll(groupId: String?, accountName: String?, synchronizable: Bool?, accessibility: String?) -> FlutterSecureStorageResponse {
        var keychainQuery = baseQuery(key: nil, groupId: groupId, accountName: accountName, synchronizable: synchronizable, accessibility: accessibility, returnData: true)
        
        keychainQuery[kSecMatchLimit] = kSecMatchLimitAll
        keychainQuery[kSecReturnAttributes] = true
        
        var ref: AnyObject?
        let status = SecItemCopyMatching(
            keychainQuery as CFDictionary,
            &ref
        )
        
        if (status == errSecItemNotFound) {
            // readAll() returns all elements, so return nil if the items does not exist
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }
        
        var results: [String: String] = [:]
        
        if (status == noErr) {
            (ref as! NSArray).forEach { item in
                let key: String = (item as! NSDictionary)[kSecAttrAccount] as! String
                let value: String = String(data: (item as! NSDictionary)[kSecValueData] as! Data, encoding: .utf8) ?? ""
                results[key] = value
            }
        }
        
        return FlutterSecureStorageResponse(status: status, value: results)
    }
    
    internal func read(key: String, groupId: String?, accountName: String?,accessControl: String?) -> FlutterSecureStorageResponse {
        // Set up the keychain query
        var keychainQuery = baseQuery(
            key: key,
            groupId: groupId,
            accountName: accountName,
            synchronizable: nil,
            accessibility: nil,
            returnData: true
        )
        
        if accessControl != nil {
                // Create an LAContext
                let context = LAContext()
                context.localizedReason = "Authenticate to access secure data"
                // Include the context in the query
                keychainQuery[kSecUseAuthenticationContext] = context
            }
        // Ensure we get the data back
        keychainQuery[kSecReturnData] = true
        
        var ref: AnyObject?
        let status = SecItemCopyMatching(keychainQuery as CFDictionary, &ref)
        
        if status == errSecSuccess {
            if let data = ref as? Data, let value = String(data: data, encoding: .utf8) {
                return FlutterSecureStorageResponse(status: status, value: value)
            } else {
                return FlutterSecureStorageResponse(status: errSecDecode, value: nil)
            }
        } else {
            return FlutterSecureStorageResponse(status: status, value: nil)
        }
    }
    
    internal func deleteAll(groupId: String?, accountName: String?) -> FlutterSecureStorageResponse {
        let keychainQuery = baseQuery(key: nil, groupId: groupId, accountName: accountName, synchronizable: nil, accessibility: nil, returnData: nil)
        let status = SecItemDelete(keychainQuery as CFDictionary)
        
        if (status == errSecItemNotFound) {
            // deleteAll() deletes all items, so return nil if the items does not exist
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }
        
        return FlutterSecureStorageResponse(status: status, value: nil)
    }
    
    internal func delete(key: String, groupId: String?, accountName: String?) -> FlutterSecureStorageResponse {
        let keychainQuery = baseQuery(key: key, groupId: groupId, accountName: accountName, synchronizable: nil, accessibility: nil, returnData: true)
        let status = SecItemDelete(keychainQuery as CFDictionary)
        
        // Return nil if the key is not found
        if (status == errSecItemNotFound) {
            return FlutterSecureStorageResponse(status: errSecSuccess, value: nil)
        }
        
        return FlutterSecureStorageResponse(status: status, value: nil)
    }
    
    internal func write(key: String, value: String, groupId: String?, accountName: String?, synchronizable: Bool?, accessibility: String?,accessControl: String?) -> FlutterSecureStorageResponse {
        // Check if the key exists
        var keyExists: Bool = false
        switch containsKey(key: key, groupId: groupId, accountName: accountName) {
        case .success(let exists):
            keyExists = exists
        case .failure(let err):
            return FlutterSecureStorageResponse(status: err.status, value: nil)
        }
    
        // Set up the keychain item
        var keychainQuery = baseQuery(
            key: key,
            groupId: groupId,
            accountName: accountName,
            synchronizable: synchronizable,
            accessibility: nil, // Accessibility is set via access control
            returnData: nil
        )
        if let accessControlStr = accessControl {
                print("STRINGAO ="+accessControlStr)
                // Create access control with specified flags
                var secAccessControlFlags: SecAccessControlCreateFlags = []
                switch accessControlStr {
                    case "user_presence":
                        secAccessControlFlags = .userPresence
                    case "biometry_any":
                        secAccessControlFlags = .biometryAny
                    case "biometry_current_set":
                        secAccessControlFlags = .biometryCurrentSet
                    case "device_passcode":
                        secAccessControlFlags = .devicePasscode
                    default:
                        secAccessControlFlags = []
                }

                var error: Unmanaged<CFError>?
                guard let accessControlObj = SecAccessControlCreateWithFlags(
                    nil,
                    parseAccessibleAttr(accessibility: accessibility),
                    secAccessControlFlags,
                    &error
                ) else {
                    return FlutterSecureStorageResponse(status: errSecParam, value: nil)
                }

                // Remove kSecAttrAccessible since we're using kSecAttrAccessControl
                keychainQuery.removeValue(forKey: kSecAttrAccessible)
                // Add access control object
                keychainQuery[kSecAttrAccessControl] = accessControlObj
            }
        
        // Set the value data
        keychainQuery[kSecValueData] = value.data(using: .utf8)
        
        // If key exists, delete it first (cannot update kSecAttrAccessControl)
        if keyExists {
            let deleteStatus = SecItemDelete(keychainQuery as CFDictionary)
            if deleteStatus != errSecSuccess && deleteStatus != errSecItemNotFound {
                return FlutterSecureStorageResponse(status: deleteStatus, value: nil)
            }
        }
        
        // Add the item to the keychain
        let status = SecItemAdd(keychainQuery as CFDictionary, nil)
        NSLog(status.description)
        return FlutterSecureStorageResponse(status: status, value: nil)
    }
}


struct FlutterSecureStorageResponse {
    var status: OSStatus?
    var value: Any?
}

struct OSSecError: Error {
    var status: OSStatus
}

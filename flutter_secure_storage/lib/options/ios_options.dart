part of '../flutter_secure_storage.dart';

/// Specific options for iOS platform.
class IOSOptions extends AppleOptions {
  const IOSOptions({
    String? groupId,
    String? accountName = AppleOptions.defaultAccountName,
    KeychainAccessibility? accessibility = KeychainAccessibility.unlocked,
    bool synchronizable = false,
    AccessControl? accessControl,
  }) : super(
          groupId: groupId,
          accountName: accountName,
          accessibility: accessibility,
          synchronizable: synchronizable,
          accessControl: accessControl,
        );

  static const IOSOptions defaultOptions = IOSOptions();

  IOSOptions copyWith({
    String? groupId,
    String? accountName,
    KeychainAccessibility? accessibility,
    bool? synchronizable,
    AccessControl? accessControl,
  }) =>
      IOSOptions(
        groupId: groupId ?? _groupId,
        accountName: accountName ?? _accountName,
        accessibility: accessibility ?? _accessibility,
        synchronizable: synchronizable ?? _synchronizable,
        accessControl: accessControl ?? _accessControl,
      );
}

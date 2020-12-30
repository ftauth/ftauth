import 'package:equatable/equatable.dart';
import 'package:json_annotation/json_annotation.dart';

import 'client_type.dart';
import 'scope.dart';

part 'client_info.g.dart';

/// ClientInfo holds information about the client.
@JsonSerializable(
  fieldRename: FieldRename.snake,
)
class ClientInfo extends Equatable {
  final String clientId;
  final String? clientName;
  final ClientType clientType;
  final String? clientSecret;
  final DateTime? clientSecretExpiresAt;
  final List<String> redirectUris;

  @JsonKey(fromJson: _scopesFromJson)
  final List<String> scopes;
  final String? jwksUri;
  final String? logoUri;
  final List<String> grantTypes;

  const ClientInfo({
    required this.clientId,
    this.clientName,
    required this.clientType,
    this.clientSecret,
    this.clientSecretExpiresAt,
    required this.redirectUris,
    required this.scopes,
    this.jwksUri,
    this.logoUri,
    required this.grantTypes,
  });

  static List<String> _scopesFromJson(dynamic json) {
    final scopes = <String>[];
    if (json is List) {
      for (var item in json) {
        if (item is String) {
          scopes.add(item);
        } else if (item is Map && item.containsKey('name')) {
          scopes.add(item['name']);
        }
      }
    }
    return scopes;
  }

  ClientInfo copyWith({
    String? clientId,
    String? clientName,
    ClientType? clientType,
    String? clientSecret,
    DateTime? clientSecretExpiresAt,
    List<String>? redirectUris,
    List<String>? scopes,
    String? jwksUri,
    String? logoUri,
    List<String>? grantTypes,
  }) {
    return ClientInfo(
      clientId: clientId ?? this.clientId,
      clientType: clientType ?? this.clientType,
      clientName: clientName ?? this.clientName,
      clientSecret: clientSecret ?? this.clientSecret,
      clientSecretExpiresAt:
          clientSecretExpiresAt ?? this.clientSecretExpiresAt,
      redirectUris: redirectUris ?? this.redirectUris,
      scopes: scopes ?? this.scopes,
      jwksUri: jwksUri ?? this.jwksUri,
      logoUri: logoUri ?? this.logoUri,
      grantTypes: grantTypes ?? this.grantTypes,
    );
  }

  factory ClientInfo.fromJson(Map<String, dynamic> json) =>
      _$ClientInfoFromJson(json);

  Map<String, dynamic> toJson() => _$ClientInfoToJson(this);

  @override
  List<Object> get props => [
        clientId,
        if (clientName != null) clientName!,
        clientType,
        if (clientSecret != null) clientSecret!,
        if (clientSecretExpiresAt != null) clientSecretExpiresAt!,
        redirectUris,
        scopes,
        if (jwksUri != null) jwksUri!,
        if (logoUri != null) logoUri!,
        grantTypes,
      ];
}

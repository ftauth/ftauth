import 'package:json_annotation/json_annotation.dart';

import 'client_type.dart';

part 'client_info.g.dart';

/// ClientInfo holds information about the client.
@JsonSerializable(
  fieldRename: FieldRename.snake,
)
class ClientInfo {
  final String clientId;
  final String clientName;
  final ClientType clientType;
  final String clientSecret;
  final DateTime clientSecretExpiresAt;
  final List<String> redirectUris;
  final List<String> scopes;
  final String jwksUri;
  final String logoUri;
  final List<String> grantTypes;

  const ClientInfo({
    this.clientId,
    this.clientName,
    this.clientType,
    this.clientSecret,
    this.clientSecretExpiresAt,
    this.redirectUris,
    this.scopes,
    this.jwksUri,
    this.logoUri,
    this.grantTypes,
  });

  factory ClientInfo.fromJson(Map<String, dynamic> json) =>
      _$ClientInfoFromJson(json);

  Map<String, dynamic> toJson() => _$ClientInfoToJson(this);
}

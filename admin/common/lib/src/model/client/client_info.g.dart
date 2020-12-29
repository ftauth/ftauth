// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'client_info.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

ClientInfo _$ClientInfoFromJson(Map<String, dynamic> json) {
  return ClientInfo(
    clientId: json['client_id'] as String,
    clientName: json['client_name'] as String?,
    clientType: _$enumDecode(_$ClientTypeEnumMap, json['client_type']),
    clientSecret: json['client_secret'] as String?,
    clientSecretExpiresAt: json['client_secret_expires_at'] == null
        ? null
        : DateTime.parse(json['client_secret_expires_at'] as String),
    redirectUris: (json['redirect_uris'] as List<dynamic>)
        .map((e) => e as String)
        .toList(),
    scopes: ClientInfo._scopesFromJson(json['scopes']),
    jwksUri: json['jwks_uri'] as String?,
    logoUri: json['logo_uri'] as String?,
    grantTypes:
        (json['grant_types'] as List<dynamic>).map((e) => e as String).toList(),
  );
}

Map<String, dynamic> _$ClientInfoToJson(ClientInfo instance) =>
    <String, dynamic>{
      'client_id': instance.clientId,
      'client_name': instance.clientName,
      'client_type': _$ClientTypeEnumMap[instance.clientType],
      'client_secret': instance.clientSecret,
      'client_secret_expires_at':
          instance.clientSecretExpiresAt?.toIso8601String(),
      'redirect_uris': instance.redirectUris,
      'scopes': instance.scopes,
      'jwks_uri': instance.jwksUri,
      'logo_uri': instance.logoUri,
      'grant_types': instance.grantTypes,
    };

K _$enumDecode<K, V>(
  Map<K, V> enumValues,
  Object? source, {
  K? unknownValue,
}) {
  if (source == null) {
    throw ArgumentError(
      'A value must be provided. Supported values: '
      '${enumValues.values.join(', ')}',
    );
  }

  return enumValues.entries.singleWhere(
    (e) => e.value == source,
    orElse: () {
      if (unknownValue == null) {
        throw ArgumentError(
          '`$source` is not one of the supported values: '
          '${enumValues.values.join(', ')}',
        );
      }
      return MapEntry(unknownValue, enumValues.values.first);
    },
  ).key;
}

const _$ClientTypeEnumMap = {
  ClientType.public: 'public',
  ClientType.confidential: 'confidential',
};

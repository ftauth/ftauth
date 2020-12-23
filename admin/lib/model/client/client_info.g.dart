// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'client_info.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

ClientInfo _$ClientInfoFromJson(Map<String, dynamic> json) {
  return ClientInfo(
    clientId: json['client_id'] as String,
    clientName: json['client_name'] as String,
    clientType: _$enumDecodeNullable(_$ClientTypeEnumMap, json['client_type']),
    clientSecret: json['client_secret'] as String,
    clientSecretExpiresAt: json['client_secret_expires_at'] == null
        ? null
        : DateTime.parse(json['client_secret_expires_at'] as String),
    redirectUris:
        (json['redirect_uris'] as List)?.map((e) => e as String)?.toList(),
    scopes: (json['scopes'] as List)?.map((e) => e as String)?.toList(),
    jwksUri: json['jwks_uri'] as String,
    logoUri: json['logo_uri'] as String,
    grantTypes:
        (json['grant_types'] as List)?.map((e) => e as String)?.toList(),
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

T _$enumDecode<T>(
  Map<T, dynamic> enumValues,
  dynamic source, {
  T unknownValue,
}) {
  if (source == null) {
    throw ArgumentError('A value must be provided. Supported values: '
        '${enumValues.values.join(', ')}');
  }

  final value = enumValues.entries
      .singleWhere((e) => e.value == source, orElse: () => null)
      ?.key;

  if (value == null && unknownValue == null) {
    throw ArgumentError('`$source` is not one of the supported values: '
        '${enumValues.values.join(', ')}');
  }
  return value ?? unknownValue;
}

T _$enumDecodeNullable<T>(
  Map<T, dynamic> enumValues,
  dynamic source, {
  T unknownValue,
}) {
  if (source == null) {
    return null;
  }
  return _$enumDecode<T>(enumValues, source, unknownValue: unknownValue);
}

const _$ClientTypeEnumMap = {
  ClientType.public: 'public',
  ClientType.confidential: 'confidential',
};

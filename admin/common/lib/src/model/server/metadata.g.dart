// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'metadata.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

AuthorizationServerMetadata _$AuthorizationServerMetadataFromJson(
    Map<String, dynamic> json) {
  return AuthorizationServerMetadata(
    issuer: json['issuer'] as String,
    authorizationEndpoint: json['authorization_endpoint'] as String,
    tokenEndpoint: json['token_endpoint'] as String,
    jwksUri: json['jwks_uri'] as String,
    registrationEndpoint: json['registration_endpoint'] as String,
    scopes: (json['scopes'] as List<dynamic>).map((e) => e as String).toList(),
    responseTypesSupported: (json['response_types_supported'] as List<dynamic>)
        .map((e) => e as String)
        .toList(),
  );
}

Map<String, dynamic> _$AuthorizationServerMetadataToJson(
        AuthorizationServerMetadata instance) =>
    <String, dynamic>{
      'issuer': instance.issuer,
      'authorization_endpoint': instance.authorizationEndpoint,
      'token_endpoint': instance.tokenEndpoint,
      'jwks_uri': instance.jwksUri,
      'registration_endpoint': instance.registrationEndpoint,
      'scopes': instance.scopes,
      'response_types_supported': instance.responseTypesSupported,
    };

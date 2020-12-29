import 'package:json_annotation/json_annotation.dart';

part 'metadata.g.dart';

@JsonSerializable(
  fieldRename: FieldRename.snake,
)
class AuthorizationServerMetadata {
  final String issuer;
  final String authorizationEndpoint;
  final String tokenEndpoint;
  final String jwksUri;
  final String registrationEndpoint;
  final List<String> scopes;
  final List<String> responseTypesSupported;

  const AuthorizationServerMetadata({
    required this.issuer,
    required this.authorizationEndpoint,
    required this.tokenEndpoint,
    required this.jwksUri,
    required this.registrationEndpoint,
    required this.scopes,
    required this.responseTypesSupported,
  });

  factory AuthorizationServerMetadata.fromJson(Map<String, dynamic> json) =>
      _$AuthorizationServerMetadataFromJson(json);

  Map<String, dynamic> toJson() => _$AuthorizationServerMetadataToJson(this);
}

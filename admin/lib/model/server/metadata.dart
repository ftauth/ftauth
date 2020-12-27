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
    this.issuer,
    this.authorizationEndpoint,
    this.tokenEndpoint,
    this.jwksUri,
    this.registrationEndpoint,
    this.scopes,
    this.responseTypesSupported,
  });

  factory AuthorizationServerMetadata.fromJson(Map<String, dynamic> json) =>
      _$AuthorizationServerMetadataFromJson(json);

  Map<String, dynamic> toJson() => _$AuthorizationServerMetadataToJson(this);
}

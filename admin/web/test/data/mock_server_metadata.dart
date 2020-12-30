import 'package:common/common.dart';

final mockServerMetadata = AuthorizationServerMetadata(
  issuer: 'localhost',
  authorizationEndpoint: 'http://localhost:8080/authorize',
  tokenEndpoint: 'http://localhost:8080/token',
  jwksUri: 'http://localhost:8080/jwks.json',
  registrationEndpoint: 'http://localhost:8080/client/register',
  scopes: ['default', 'admin'],
  responseTypesSupported: ['authorization_code', 'refresh_token'],
);

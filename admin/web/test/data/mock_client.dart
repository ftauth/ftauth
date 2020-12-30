import 'package:common/common.dart';

var mockClientInfo = ClientInfo(
  clientId: '1234',
  clientType: ClientType.public,
  redirectUris: ['http://localhost:8080/auth'],
  scopes: ['default', 'admin'],
  grantTypes: ['authorization_code', 'token'],
);

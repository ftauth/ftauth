import 'package:common/common.dart';

void main() {
  var mockClientInfo = ClientInfo(
    clientId: '1234',
    clientType: ClientType.public,
    redirectUris: [],
    scopes: ['default', 'admin'],
    grantTypes: ['authorization_code', 'token'],
  );
}

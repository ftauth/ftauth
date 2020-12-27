import 'package:admin/model/client/client_info.dart';
import 'package:admin/model/model.dart';

import 'config_repo.dart';

class ConfigRepositoryImpl extends ConfigRepository {
  @override
  Future<ClientInfo> loadConfig() async {
    return ClientInfo(
      clientId: 'ee1de5ad-c4a8-415c-8ff6-769ca0fd3bf1',
      clientType: ClientType.public,
      redirectUris: ['http://localhost:8080/#/auth'],
      scopes: ['default', 'admin'],
    );
  }
}

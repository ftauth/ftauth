import 'package:admin/util/json.dart';
import 'package:common/common.dart';
import 'package:flutter/services.dart';

import 'config_repo.dart';

class ConfigRepositoryImpl extends ConfigRepository {
  // Cache in-memory only so it can be swapped out/changed whenever.
  ClientInfo _cached;

  @override
  Future<ClientInfo> loadConfig() async {
    if (_cached == null) {
      final configStr = await rootBundle.loadString('assets/config.json');
      final configMap = decodeJSON(configStr);
      _cached = ClientInfo.fromJson(configMap['oauth']);
    }
    return _cached;
  }
}

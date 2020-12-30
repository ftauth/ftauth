import 'dart:html';

import 'package:admin/util/json.dart';
import 'package:common/common.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'config_repo.dart';

part 'config_repo_impl_web.dart';

class ConfigRepositoryImpl extends ConfigRepository {
  factory ConfigRepositoryImpl() {
    if (kIsWeb) {
      return ConfigRepositoryWebImpl();
    }
    return ConfigRepositoryImpl._();
  }

  ConfigRepositoryImpl._();

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

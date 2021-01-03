part of 'config_repo_impl.dart';

class ConfigRepositoryWebImpl extends ConfigRepositoryImpl {
  // Cache in-memory only so it can be swapped out/changed whenever.
  ClientInfo _cached;

  ConfigRepositoryWebImpl() : super._();

  @override
  Future<ClientInfo> loadConfig() async {
    if (_cached == null) {
      final config = await super.loadConfig();
      _cached = config.copyWith(
        redirectUris: [
          'http://${window.location.host}/#/auth',
          ...config.redirectUris,
        ],
      );
    }
    return _cached;
  }
}

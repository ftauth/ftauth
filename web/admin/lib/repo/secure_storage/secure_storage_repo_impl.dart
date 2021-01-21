import 'package:hive/hive.dart';

import 'secure_storage_repo.dart';

class SecureStorageRepositoryImpl extends SecureStorageRepository {
  Future<Box<String>> openBox() => Hive.openBox<String>('ftauth');

  @override
  Future<String> getString(String key) async {
    var box = await openBox();
    return box.get(key);
  }

  @override
  Future<void> setString(String key, String value) async {
    var box = await openBox();
    return box.put(key, value);
  }

  @override
  Future<void> deleteKey(String key) async {
    var box = await openBox();
    return box.delete(key);
  }
}

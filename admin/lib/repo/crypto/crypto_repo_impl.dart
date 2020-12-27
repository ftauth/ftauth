import 'package:cryptography/cryptography.dart';

import 'crypto_repo.dart';

class CryptoRepositoryImpl extends CryptoRepository {
  @override
  Future<PrivateKey> generatePrivateKey() async {
    final keyPair = await RsaPss(sha256).newKeyPair(modulusLength: 4096);
    return keyPair.privateKey;
  }
}

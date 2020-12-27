import 'package:admin/model/server/metadata.dart';
import 'package:jose/jose.dart';

abstract class MetadataRepo {
  Future<AuthorizationServerMetadata> loadServerMetadata({bool force});
  Future<AuthorizationServerMetadata> updateServerMetadata(
    AuthorizationServerMetadata metadata,
  );
  Future<JsonWebKeyStore> loadKeyStore();
}

import 'package:admin/model/server/metadata.dart';

abstract class MetadataRepo {
  Future<AuthorizationServerMetadata> loadServerMetadata({bool force});
  Future<AuthorizationServerMetadata> updateServerMetadata(
    AuthorizationServerMetadata metadata,
  );
}

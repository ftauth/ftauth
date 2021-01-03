import 'package:admin/bloc/auth/auth_cubit.dart';
import 'package:admin/repo/auth/auth_repo_impl.dart';
import 'package:admin/repo/config/config_repo.dart';
import 'package:admin/repo/metadata/metadata_repo.dart';
import 'package:admin/repo/secure_storage/secure_storage_repo.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';

import '../data/mock_client.dart';
import '../data/mock_server_metadata.dart';

class MockStorageRepo extends Mock implements SecureStorageRepository {}

class MockMetadataRepo extends Mock implements MetadataRepo {}

class MockConfigRepo extends Mock implements ConfigRepository {}

void main() {
  final _storageRepo = MockStorageRepo();
  final _metadataRepo = MockMetadataRepo();
  final _configRepo = MockConfigRepo();
  final _authRepoImpl = AuthRepositoryImpl(
    _storageRepo,
    _metadataRepo,
    _configRepo,
  );

  setUp(() {
    reset(_storageRepo);
  });

  when(_metadataRepo.loadServerMetadata()).thenAnswer(
    (_) async => mockServerMetadata,
  );
  when(_configRepo.loadConfig()).thenAnswer(
    (_) async => mockClientInfo,
  );

  test('No stored data', () async {
    when(_storageRepo.getString(any)).thenAnswer(
      (_) async => null,
    );

    final state = await _authRepoImpl.initialize();
    expect(state, AuthSignedOut());
  });

  test('State and code verifier stored', () async {
    when(_storageRepo.getString('code_verifier')).thenAnswer(
      (_) async => 'code',
    );
    when(_storageRepo.getString('state')).thenAnswer(
      (_) async => 'state',
    );

    final state = await _authRepoImpl.initialize();
    expect(state, AuthStarted());
  });
}

import 'package:admin/bloc/auth/auth_cubit.dart';
import 'package:admin/repo/auth/auth_repo.dart';
import 'package:bloc_test/bloc_test.dart';
import 'package:common/common.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';

class MockAuthRepo extends Mock implements AuthRepository {}

void main() {
  final _authRepo = MockAuthRepo();

  const mockAuthUrl = 'http://localhost:8000/authorize';
  const mockQueryParams = {
    'code': 'code',
    'state': 'state',
  };

  setUp(() {
    reset(_authRepo);
  });

  group('initialize', () {
    blocTest<AuthCubit, AuthState>(
      'Emits value',
      build: () {
        when(_authRepo.initialize()).thenAnswer(
          (_) async => AuthSignedOut(),
        );
        return AuthCubit(_authRepo);
      },
      act: (cubit) => cubit.initialize(),
      expect: [
        AuthLoading.initializing(),
        AuthSignedOut(),
      ],
    );

    blocTest<AuthCubit, AuthState>(
      'Emits error',
      build: () {
        when(_authRepo.initialize()).thenAnswer(
          (_) async => throw Exception(),
        );
        return AuthCubit(_authRepo);
      },
      act: (cubit) => cubit.initialize(),
      expect: [
        AuthLoading.initializing(),
        AuthFailure.fromException(Exception()),
      ],
    );
  });

  group('loadLoginUrl', () {
    blocTest<AuthCubit, AuthState>(
      'returns String',
      build: () {
        when(_authRepo.initialize()).thenAnswer((_) async => AuthSignedOut());
        when(_authRepo.getAuthorizationURL())
            .thenAnswer((_) async => mockAuthUrl);

        return AuthCubit(_authRepo);
      },
      act: (cubit) async {
        await cubit.initialize();
        await cubit.loadLoginUrl();
      },
      expect: [
        AuthLoading.initializing(),
        AuthSignedOut(),
        AuthLoading.loadingUrl(),
        AuthStarted(),
      ],
    );

    blocTest<AuthCubit, AuthState>(
      'returns Exception',
      build: () {
        when(_authRepo.initialize()).thenAnswer((_) async => AuthSignedOut());
        when(_authRepo.getAuthorizationURL())
            .thenAnswer((_) async => throw Exception());

        return AuthCubit(_authRepo);
      },
      act: (cubit) async {
        await cubit.initialize();
        await cubit.loadLoginUrl();
      },
      expect: [
        AuthLoading.initializing(),
        AuthSignedOut(),
        AuthLoading.loadingUrl(),
        AuthFailure.fromException(Exception()),
      ],
    );
  });

  group('exchangeToken', () {
    blocTest<AuthCubit, AuthState>(
      'Uninitialized',
      build: () {
        when(_authRepo.initialize()).thenAnswer((_) async => AuthSignedOut());

        return AuthCubit(_authRepo);
      },
      act: (cubit) async {
        await cubit.initialize();
        await cubit.exchangeToken({});
      },
      expect: [
        AuthLoading.initializing(),
        AuthSignedOut(),
        AuthFailure.fromException(AuthException.uninitialized()),
      ],
    );

    blocTest<AuthCubit, AuthState>(
      'Loading auth URL failed',
      build: () {
        when(_authRepo.initialize()).thenAnswer(
          (_) async => AuthSignedOut(),
        );

        when(_authRepo.getAuthorizationURL())
            .thenAnswer((_) async => throw Exception());

        return AuthCubit(_authRepo);
      },
      act: (cubit) async {
        await cubit.initialize();
        await cubit.loadLoginUrl();
        await cubit.exchangeToken(mockQueryParams);
      },
      expect: [
        AuthLoading.initializing(),
        AuthSignedOut(),
        AuthLoading.loadingUrl(),
        AuthFailure.fromException(Exception()),
        AuthFailure.fromException(AuthException.uninitialized()),
      ],
    );

    blocTest<AuthCubit, AuthState>(
      'Success',
      build: () {
        when(_authRepo.initialize()).thenAnswer((_) async => AuthStarted());
        when(_authRepo.exchangeToken(any)).thenAnswer((_) async {});

        return AuthCubit(_authRepo);
      },
      act: (cubit) async {
        await cubit.initialize();
        await cubit.exchangeToken(mockQueryParams);
      },
      expect: [
        AuthLoading.initializing(),
        AuthStarted(),
        AuthLoading.loggingIn(),
        AuthSignedIn(),
      ],
    );

    blocTest<AuthCubit, AuthState>(
      'Error',
      build: () {
        when(_authRepo.initialize()).thenAnswer((_) async => AuthStarted());
        when(_authRepo.exchangeToken(any))
            .thenAnswer((_) async => throw Exception());

        return AuthCubit(_authRepo);
      },
      act: (cubit) async {
        await cubit.initialize();
        await cubit.exchangeToken(mockQueryParams);
      },
      expect: [
        AuthLoading.initializing(),
        AuthStarted(),
        AuthLoading.loggingIn(),
        AuthFailure.fromException(Exception()),
      ],
    );
  });
}

import 'package:admin/model/exception.dart';
import 'package:admin/repo/auth/auth_repo.dart';
import 'package:bloc/bloc.dart';
import 'package:equatable/equatable.dart';

part 'auth_state.dart';

class AuthCubit extends Cubit<AuthState> {
  final AuthRepository _authRepo;

  AuthCubit(this._authRepo) : super(AuthInitial());

  final List<AuthState> history = [AuthInitial()];
  Future<void> get isInitialized =>
      firstWhere((state) => state is! AuthInitial);

  @override
  void onChange(Change<AuthState> change) {
    super.onChange(change);
    history.add(change.nextState);
  }

  Stream<AuthState> get allStates async* {
    yield* Stream.fromIterable(history);
    yield* this;
  }

  Stream<AuthState> get states async* {
    yield state;
    yield* this;
  }

  Future<void> initialize() async {
    if (state is AuthInitial) {
      emit(AuthLoading('Checking if logged in...'));
      print('Initializing...');
      final currentState = await _authRepo.initialize();
      print('Current auth state is: $currentState');
      emit(currentState);
    }
  }

  Future<String> loadLoginUrl() async {
    emit(AuthLoading('Retrieving login URL...'));
    final authUrl = await _authRepo.getAuthorizationURL();
    emit(AuthStarted());
    return authUrl.toString();
  }

  Future<void> exchangeToken(Map<String, String> queryParameters) async {
    if (state is! AuthStarted) {
      emit(AuthFailure(AuthException.uninitialized()));
      return;
    }

    emit(AuthLoading('Logging in...'));
    try {
      await _authRepo.exchangeToken(queryParameters);
      emit(AuthSignedIn());
    } on AuthException catch (e) {
      emit(AuthFailure(e));
    }
  }

  void handleAuthorizationError(Map<String, String> queryParams) {
    final error = queryParams['error'];
    final errorDetails = queryParams['error_description'] ?? 'No details';
    emit(AuthFailure(AuthException('$error: $errorDetails')));
  }

  Future<void> logout() async {
    await _authRepo.logout();
    emit(AuthSignedOut());
  }
}

part of 'auth_cubit.dart';

abstract class AuthState extends Equatable {
  const AuthState();

  @override
  List<Object> get props => [];
}

class AuthInitial extends AuthState {}

// Used when exchanging tokens or loading saved state
class AuthLoading extends AuthState {
  final String message;

  const AuthLoading(this.message);

  const AuthLoading.initializing() : message = 'Checking if logged in...';
  const AuthLoading.loadingUrl() : message = null;
  const AuthLoading.loggingIn() : message = 'Logging in...';

  @override
  List<Object> get props => [message];
}

class AuthStarted extends AuthState {}

class AuthSignedIn extends AuthState {}

class AuthSignedOut extends AuthState {}

class AuthFailure extends AuthState {
  final String message;

  const AuthFailure([this.message = 'An unknown error occurred.']);

  factory AuthFailure.fromException(Exception e) => AuthFailure(e.toString());

  @override
  List<Object> get props => [message];
}

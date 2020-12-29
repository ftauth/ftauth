part of 'client_list_cubit.dart';

abstract class ClientListState extends Equatable {
  const ClientListState();

  @override
  List<Object> get props => [];
}

class ClientListLoading extends ClientListState {}

class ClientListLoaded extends ClientListState {
  final List<ClientInfo> clients;

  ClientListLoaded(this.clients);

  @override
  List<Object> get props => [clients];
}

class ClientListFailure extends ClientListState {
  final String message;

  ClientListFailure(this.message);

  @override
  List<Object> get props => [message];
}

part of 'client_cubit.dart';

abstract class ClientState extends Equatable {
  const ClientState();

  @override
  List<Object> get props => [];

  ClientInfo get clientInfo;
}

class ClientLoading extends ClientState {
  @override
  ClientInfo get clientInfo => null;
}

class ClientLoaded extends ClientState {
  final ClientInfo _clientInfo;

  ClientLoaded(this._clientInfo);

  @override
  List<Object> get props => [_clientInfo];

  @override
  ClientInfo get clientInfo => _clientInfo;
}

class ClientSaving extends ClientState {
  final ClientInfo _clientInfo;

  ClientSaving(this._clientInfo);

  @override
  List<Object> get props => [_clientInfo];

  @override
  ClientInfo get clientInfo => _clientInfo;
}

class ClientFailure extends ClientState {
  final Exception exception;
  final ClientInfo _clientInfo;

  ClientFailure(this.exception, [this._clientInfo]);

  @override
  List<Object> get props => [exception, _clientInfo];

  @override
  ClientInfo get clientInfo => _clientInfo;
}

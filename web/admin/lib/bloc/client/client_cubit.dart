import 'package:admin/repo/client/client_repo.dart';
import 'package:ftauth/ftauth.dart';
import 'package:bloc/bloc.dart';
import 'package:equatable/equatable.dart';

part 'client_state.dart';

class ClientCubit extends Cubit<ClientState> {
  final ClientRepo _clientRepo;
  final String clientId;
  ClientInfo _clientInfo;

  ClientCubit(
    this._clientRepo,
    this.clientId, {
    ClientInfo clientInfo,
  })  : _clientInfo = clientInfo,
        super(ClientLoading());

  Future<void> getClientInfo() async {
    if (_clientInfo == null) {
      emit(ClientLoading());
      try {
        _clientInfo = await _clientRepo.getClientInfo(clientId);
        emit(ClientLoaded(_clientInfo));
      } on Exception catch (e) {
        emit(ClientFailure(e));
      }
    } else {
      emit(ClientLoaded(_clientInfo));
    }
  }

  Future<void> registerClient() async {
    emit(ClientSaving(_clientInfo));
    try {
      _clientInfo = await _clientRepo.registerClient(_clientInfo);
      emit(ClientLoaded(_clientInfo));
    } on Exception catch (e) {
      emit(ClientFailure(e));
    }
  }

  Future<void> updateClient() async {
    emit(ClientSaving(_clientInfo));
    try {
      _clientInfo = await _clientRepo.updateClient(_clientInfo);
      emit(ClientLoaded(_clientInfo));
    } on Exception catch (e) {
      emit(ClientFailure(e));
    }
  }

  Future<void> deleteClient() async {
    try {
      await _clientRepo.deleteClient(_clientInfo);
    } on Exception catch (e) {
      emit(ClientFailure(e));
    }
  }

  void updateFormState({
    String clientId,
    String clientName,
    ClientType clientType,
    String clientSecret,
    DateTime clientSecretExpiresAt,
    List<String> redirectUris,
    List<String> scopes,
    String jwksUri,
    String logoUri,
    List<String> grantTypes,
  }) {
    emit(
      ClientLoaded(
        _clientInfo.copyWith(
          clientId: clientId,
          clientName: clientName,
          clientType: clientType,
          clientSecret: clientSecret,
          clientSecretExpiresAt: clientSecretExpiresAt,
          redirectUris: redirectUris,
          scopes: scopes,
          jwksUri: jwksUri,
          logoUri: logoUri,
          grantTypes: grantTypes,
        ),
      ),
    );
  }
}

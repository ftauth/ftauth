import 'package:admin/model/model.dart';
import 'package:admin/repo/client/client_repo.dart';
import 'package:bloc/bloc.dart';
import 'package:equatable/equatable.dart';

part 'client_state.dart';

class ClientCubit extends Cubit<ClientState> implements ClientRepo {
  final ClientRepo _clientRepo;

  ClientCubit(this._clientRepo) : super(ClientLoading());

  @override
  Future<ClientInfo> getClientInfo(String id) async {
    emit(ClientLoading());
    try {
      final ClientInfo clientInfo = await _clientRepo.getClientInfo(id);
      emit(ClientLoaded(clientInfo));
      return clientInfo;
    } on Exception catch (e) {
      emit(ClientError(e));
      return null;
    }
  }

  @override
  Future<ClientInfo> registerClient(ClientInfo clientInfo) async {
    emit(ClientSaving(clientInfo));
    try {
      final ClientInfo registeredClient =
          await _clientRepo.registerClient(clientInfo);
      emit(ClientLoaded(registeredClient));
      return registeredClient;
    } on Exception catch (e) {
      emit(ClientError(e, clientInfo));
      return clientInfo;
    }
  }

  @override
  Future<ClientInfo> updateClient(ClientInfo clientInfo) async {
    emit(ClientSaving(clientInfo));
    try {
      final ClientInfo updatedClient =
          await _clientRepo.updateClient(clientInfo);
      emit(ClientLoaded(updatedClient));
      return updatedClient;
    } on Exception catch (e) {
      emit(ClientError(e, clientInfo));
      return clientInfo;
    }
  }

  @override
  Future<void> deleteClient(ClientInfo clientInfo) async {
    try {
      await _clientRepo.deleteClient(clientInfo);
    } on Exception catch (e) {
      emit(ClientError(e, clientInfo));
    }
  }
}

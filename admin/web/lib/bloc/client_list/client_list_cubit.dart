import 'package:common/common.dart';
import 'package:admin/repo/client/client_repo.dart';
import 'package:bloc/bloc.dart';
import 'package:equatable/equatable.dart';

part 'client_list_state.dart';

class ClientListCubit extends Cubit<ClientListState> {
  final ClientRepo _clientRepo;

  ClientListCubit(this._clientRepo) : super(ClientListLoading());

  Future<void> loadClients({bool force = false}) async {
    if (state is ClientListLoaded && !force) {
      return;
    }
    emit(ClientListLoading());
    try {
      final clients = await _clientRepo.listClients();
      emit(ClientListLoaded(clients));
    } on Exception catch (e) {
      emit(ClientListFailure(e.toString()));
    }
  }
}

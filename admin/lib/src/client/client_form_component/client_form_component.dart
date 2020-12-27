import 'package:admin/bloc/auth/auth_cubit.dart';
import 'package:admin/bloc/client/client_cubit.dart';
import 'package:admin/model/model.dart';
import 'package:admin/repo/client/client_repo.dart';
import 'package:admin/repo/metadata/metadata_repo.dart';
import 'package:admin/src/route_paths.dart';
import 'package:angular/angular.dart';
import 'package:angular_bloc/angular_bloc.dart';
import 'package:angular_components/angular_components.dart';
import 'package:angular_forms/angular_forms.dart';
import 'package:angular_router/angular_router.dart';

@Component(
  selector: 'client-form',
  templateUrl: 'client_form_component.html',
  styleUrls: [
    'client_form_component.css',
  ],
  directives: [
    coreDirectives,
    formDirectives,
    materialInputDirectives,
    MaterialButtonComponent,
    MaterialIconComponent,
  ],
  pipes: [BlocPipe],
)
class ClientRegisterFormComponent implements OnActivate, OnDestroy {
  final Location _location;
  final MetadataRepo metadataRepo;
  final AuthCubit _authCubit;
  final ClientCubit clientCubit;

  ClientRegisterFormComponent(
    ClientRepo clientRepo,
    this.metadataRepo,
    this._location,
    this._authCubit,
  ) : clientCubit = ClientCubit(clientRepo);

  ClientInfo get clientInfo => clientCubit.state.clientInfo;

  bool _isLoading = true;
  bool get isLoading {
    if (clientCubit.state is ClientLoading) {
      return true;
    }
    return _isLoading;
  }

  bool get isSaving => clientCubit.state is ClientSaving;

  String _error;
  String get error {
    if (clientCubit.state is ClientFailure) {
      return (clientCubit.state as ClientFailure).exception.toString();
    }
    return _error;
  }

  AuthorizationServerMetadata metadata;

  Future<void> loadMetadata() async {
    try {
      metadata = await metadataRepo.loadServerMetadata();
    } catch (e) {
      _error = e.toString();
    }
    _isLoading = false;
  }

  @override
  void onActivate(RouterState previous, RouterState current) async {
    await _authCubit.isInitialized;
    print('Loading client metadata...');
    final clientId = current.parameters[clientIdParam];
    if (clientId == null) {
      _error = 'Client ID not specified';
      return;
    }
    await clientCubit.getClientInfo(clientId);
  }

  @override
  void ngOnDestroy() {
    clientCubit.close();
  }
}

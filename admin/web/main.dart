import 'dart:html';

import 'package:admin/bloc/auth/auth_cubit.dart';
import 'package:admin/model/config/config.dart';
import 'package:admin/repo/auth/auth_repo.dart';
import 'package:admin/repo/auth/auth_repo_impl.dart';
import 'package:admin/repo/client/client_repo.dart';
import 'package:admin/repo/client/client_repo_impl.dart';
import 'package:admin/repo/config/config_repo.dart';
import 'package:admin/repo/config/config_repo_impl.dart';
import 'package:admin/repo/crypto/crypto_repo.dart';
import 'package:admin/repo/crypto/crypto_repo_impl.dart';
import 'package:admin/repo/metadata/metadata_repo.dart';
import 'package:admin/repo/metadata/metadata_repo_impl.dart';
import 'package:admin/repo/secure_storage/secure_storage_repo.dart';
import 'package:admin/repo/secure_storage/secure_storage_repo_impl.dart';
import 'package:angular/angular.dart';
import 'package:admin/app_component.template.dart' as ng;
import 'package:angular_router/angular_router.dart';
import 'package:http/browser_client.dart';
import 'package:http/http.dart' as http;

import 'main.template.dart' as self;

bool get _isDevMode {
  var enabled = false;
  assert(enabled = true);
  return enabled;
}

@GenerateInjector(
  [
    ClassProvider(http.Client, useClass: BrowserClient),
    ClassProvider(MetadataRepo, useClass: MetadataRepoImpl),
    FactoryProvider(AppConfig, getAppConfig),
    ClassProvider(AuthRepository, useClass: AuthRepositoryImpl),
    ClassProvider(SecureStorageRepository,
        useClass: SecureStorageRepositoryImpl),
    ClassProvider(CryptoRepository, useClass: CryptoRepositoryImpl),
    ClassProvider(ConfigRepository, useClass: ConfigRepositoryImpl),
    ClassProvider(AuthCubit),
    ClassProvider(ClientRepo, useClass: ClientRepoImpl),
    routerProviders,
    FactoryProvider(LocationStrategy, createLocationStrategy),
  ],
)
final InjectorFactory injector = self.injector$Injector;

LocationStrategy createLocationStrategy(
  PlatformLocation platformLocation,
  @Optional() String baseUrl,
) {
  if (_isDevMode) {
    return HashLocationStrategy(platformLocation, baseUrl);
  } else {
    return PathLocationStrategy(platformLocation, baseUrl);
  }
}

AppConfig getAppConfig() {
  if (_isDevMode) {
    return AppConfig.dev();
  } else {
    return AppConfig.prod();
  }
}

void main() {
  runApp(
    ng.AppComponentNgFactory,
    createInjector: injector,
  );
}

import 'dart:html';

import 'package:admin/repo/client/client_repo.dart';
import 'package:admin/repo/client/client_repo_impl.dart';
import 'package:admin/repo/metadata/metadata_repo.dart';
import 'package:admin/repo/metadata/metadata_repo_impl.dart';
import 'package:angular/angular.dart';
import 'package:admin/app_component.template.dart' as ng;
import 'package:angular_router/angular_router.dart';
import 'package:http/browser_client.dart';

import 'main.template.dart' as self;

bool get _isDevMode {
  var enabled = false;
  assert(enabled = true);
  return enabled;
}

@GenerateInjector(
  [
    FactoryProvider(MetadataRepo, createMetadataRepo),
    ClassProvider(ClientRepo, useClass: ClientRepoImpl),
    routerProviders,
    FactoryProvider(LocationStrategy, createLocationStrategy),
  ],
)
final InjectorFactory injector = self.injector$Injector;

final _metadataRepo = MetadataRepoImpl(
  BrowserClient(),
  'http://${window.location.host}',
);
MetadataRepo createMetadataRepo() => _metadataRepo;

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

void main() {
  runApp(
    ng.AppComponentNgFactory,
    createInjector: injector,
  );
}

import 'package:admin/src/routes.dart';
import 'package:angular/angular.dart';
import 'package:angular_components/angular_components.dart';
import 'package:angular_router/angular_router.dart';

import 'src/route_paths.dart';

@Component(
  selector: 'my-app',
  styleUrls: [
    'app_component.css',
    'package:angular_components/app_layout/layout.scss.css',
  ],
  templateUrl: 'app_component.html',
  directives: [
    DeferredContentAware,
    DeferredContentDirective,
    MaterialIconComponent,
    MaterialButtonComponent,
    MaterialPersistentDrawerDirective,
    MaterialListComponent,
    MaterialListItemComponent,
    routerDirectives,
  ],
  exports: [
    RoutePaths,
    Routes,
  ],
)
class AppComponent {}

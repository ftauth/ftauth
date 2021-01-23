import 'package:admin/app_state.dart';
import 'package:admin/bloc/client_list/client_list_cubit.dart';
import 'package:admin/bloc/observer.dart';
import 'package:admin/config/config.dart';
import 'package:admin/repo/client/client_repo_impl.dart';
import 'package:admin/routes/routes.dart';
import 'package:equatable/equatable.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:ftauth_flutter/ftauth_flutter.dart';
import 'package:provider/provider.dart';

Future<void> main() async {
  Bloc.observer = MyBlocObserver();
  EquatableConfig.stringify = true;

  final config = FTAuthConfig(
    gatewayUrl: 'http://localhost:8000',
    clientId: '12cb5a11-9e2c-4f46-a0e0-1c35db45d146',
    redirectUri: kReleaseMode
        ? 'http://localhost:8080/auth'
        : 'http://localhost:8080/#/auth',
    scopes: ['default', 'admin'],
    grantTypes: ['authorization_code', 'refresh_token'],
  );

  await FTAuth.initFlutter(config: config);

  runApp(
    FTAuth(
      config: config,
      child: AdminApp(),
    ),
  );
}

AppConfig config = AppConfig.dev();

class AdminApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider.value(value: AppState()),
        Provider(
          create: (context) => ClientRepoImpl(
            FTAuth.of(context).authStates,
            config,
          ),
        ),
      ],
      child: MultiBlocProvider(
        providers: [
          BlocProvider<ClientListCubit>(
            create: (context) => ClientListCubit(
              Provider.of<ClientRepoImpl>(context, listen: false),
            ),
          ),
        ],
        child: Builder(
          builder: (context) {
            final appState = Provider.of<AppState>(context, listen: false);
            return MaterialApp.router(
              title: 'Admin',
              theme: ThemeData(
                primarySwatch: Colors.blue,
              ),
              routerDelegate: AdminRouterDelegate(appState),
              routeInformationParser: AdminRouteInformationParser(appState),
              debugShowCheckedModeBanner: false,
            );
          },
        ),
      ),
    );
  }
}

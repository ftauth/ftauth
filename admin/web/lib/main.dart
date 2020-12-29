import 'package:admin/bloc/observer.dart';
import 'package:admin/config/config.dart';
import 'package:admin/repo/auth/auth_repo_impl.dart';
import 'package:admin/repo/config/config_repo_impl.dart';
import 'package:admin/repo/metadata/metadata_repo_impl.dart';
import 'package:admin/repo/secure_storage/secure_storage_repo_impl.dart';
import 'package:admin/routes.dart';
import 'package:admin/screens/auth/auth_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:admin/bloc/auth/auth_cubit.dart';
import 'package:hive/hive.dart';
import 'package:provider/provider.dart';
import 'package:hive_flutter/hive_flutter.dart';

void main() {
  Hive.initFlutter();
  Bloc.observer = MyBlocObserver();
  runApp(AdminApp());
}

AppConfig config = AppConfig.dev();

class AdminApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    final app = MaterialApp(
      title: 'Admin',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: AuthScreen(AuthRouteInfo.empty()),
    );
    return MultiProvider(
      providers: [
        Provider(
          create: (_) => SecureStorageRepositoryImpl(),
        ),
        Provider(
          create: (_) => MetadataRepoImpl(config),
        ),
        Provider(
          create: (_) => ConfigRepositoryImpl(),
        ),
        Provider(
          create: (context) => AuthRepositoryImpl(
            Provider.of<SecureStorageRepositoryImpl>(context, listen: false),
            Provider.of<MetadataRepoImpl>(context, listen: false),
            Provider.of<ConfigRepositoryImpl>(context, listen: false),
          ),
        )
      ],
      child: MultiBlocProvider(
        providers: [
          BlocProvider<AuthCubit>(
            create: (context) => AuthCubit(
              Provider.of<AuthRepositoryImpl>(context, listen: false),
            ),
          ),
        ],
        child: app,
      ),
    );
  }
}

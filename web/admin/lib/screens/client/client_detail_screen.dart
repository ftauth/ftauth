import 'package:admin/bloc/client/client_cubit.dart';
import 'package:admin/repo/client/client_repo_impl.dart';
import 'package:admin/routes/routes.dart';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:ftauth_flutter/ftauth_flutter.dart';
import 'package:provider/provider.dart';

import 'client_detail_view.dart';

class ClientDetailScreen extends StatefulWidget {
  final ClientRouteInfo routeInfo;

  ClientDetailScreen(this.routeInfo)
      : assert(routeInfo != ClientRouteInfo.unknown());

  @override
  _ClientDetailScreenState createState() => _ClientDetailScreenState();
}

class _ClientDetailScreenState extends State<ClientDetailScreen> {
  ClientCubit cubit;

  @override
  void initState() {
    super.initState();
    cubit = ClientCubit(
      Provider.of<ClientRepoImpl>(context, listen: false),
      widget.routeInfo.clientId,
      clientInfo: widget.routeInfo.clientInfo,
    );
    cubit.getClientInfo();
  }

  @override
  Widget build(BuildContext context) {
    return BlocProvider.value(value: cubit, child: ClientDetailView());
  }
}

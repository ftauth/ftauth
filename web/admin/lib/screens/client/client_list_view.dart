import 'package:admin/app_state.dart';
import 'package:admin/bloc/client_list/client_list_cubit.dart';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:provider/provider.dart';

class ClientListView extends StatefulWidget {
  @override
  _ClientListViewState createState() => _ClientListViewState();
}

class _ClientListViewState extends State<ClientListView> {
  @override
  void initState() {
    super.initState();
    loadClients();
  }

  Future<void> loadClients() async {
    final clientListCubit =
        BlocProvider.of<ClientListCubit>(context);
    return clientListCubit.loadClients();
  }

  @override
  Widget build(BuildContext context) {
    return BlocBuilder<ClientListCubit, ClientListState>(
      builder: (context, state) {
        if (state is ClientListLoading) {
          return Center(child: CircularProgressIndicator());
        } else if (state is ClientListFailure) {
          return Center(child: Text('Error loading clients: ${state.message}'));
        }

        return ListView(
          children: [
            for (var client in (state as ClientListLoaded).clients)
              ListTile(
                title: Text(client.clientName),
                subtitle: Text(client.clientId),
                trailing: Icon(Icons.chevron_right),
                onTap: () {
                  Provider.of<AppState>(context, listen: false).selectClient(
                    client.clientId,
                    clientInfo: client,
                  );
                },
              ),
          ],
        );
      },
    );
  }
}

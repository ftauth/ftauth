import 'package:admin/bloc/client/client_cubit.dart';
import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:common/common.dart';
import 'package:admin/util/list.dart';
import 'package:provider/provider.dart';

class ClientDetailView extends StatefulWidget {
  @override
  _ClientDetailViewState createState() => _ClientDetailViewState();
}

class _ClientDetailViewState extends State<ClientDetailView> {
  bool _isEditing = false;
  bool _showSecret = false;

  @override
  Widget build(BuildContext context) {
    return BlocBuilder<ClientCubit, ClientState>(
      builder: (context, state) {
        Widget body;
        String title = 'Client Detail';
        if (state is ClientLoading || state is ClientSaving) {
          body = Center(child: CircularProgressIndicator());
        } else if (state is ClientFailure) {
          body = Center(
            child: Text('Error loading client: ${state.exception.toString()}'),
          );
        } else {
          final cubit = Provider.of<ClientCubit>(context);
          final client = (state as ClientLoaded).clientInfo;
          title = client.clientName == '' ? 'Client Detail' : client.clientName;
          body = Padding(
            padding: const EdgeInsets.all(10.0),
            child: ListView(
              children: <Widget>[
                FormGroup(
                  title: 'Client Name',
                  value: client.clientName,
                  isEditing: _isEditing,
                  onChanged: (String name) {
                    cubit.updateFormState(clientName: name);
                  },
                ),
                FormGroup(
                  title: 'Client ID',
                  value: client.clientId,
                  isEditing: false,
                  onChanged: print,
                ),
                FormGroup(
                  title: 'Client Type',
                  value: client.clientType.stringify,
                  isEditing: _isEditing,
                ),
                if (client.clientType == ClientType.confidential)
                  FormGroup(
                    title: 'Client Secret',
                    value: client.clientSecret,
                    isEditing: false,
                    child: StatefulBuilder(
                      builder: (context, setState) {
                        if (_showSecret) {
                          return Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              SelectableText(client.clientSecret),
                              const SizedBox(height: 5),
                              SelectableText(
                                client.clientSecretExpiresAt.toIso8601String(),
                              ),
                            ],
                          );
                        }
                        return Align(
                          alignment: Alignment.centerLeft,
                          child: LimitedBox(
                            maxWidth: 50,
                            child: RaisedButton(
                              onPressed: () {
                                setState(() => _showSecret = true);
                              },
                              child: Text('Show'),
                            ),
                          ),
                        );
                      },
                    ),
                  ),
                MultiFormGroup(
                  title: 'Redirect URIs',
                  value: client.redirectUris,
                  isEditing: _isEditing,
                  onChanged: (List<String> redirectUris) {
                    cubit.updateFormState(redirectUris: redirectUris);
                  },
                  headerButton: IconButton(
                    icon: Icon(Icons.add_circle_outline),
                    onPressed: () {
                      cubit.updateFormState(
                        redirectUris: [...client.redirectUris, ''],
                      );
                    },
                  ),
                ),
                MultiFormGroup(
                  title: 'Scopes',
                  value: client.scopes,
                  isEditing: _isEditing,
                  onChanged: (List<String> scopes) {
                    cubit.updateFormState(scopes: scopes);
                  },
                ),
                MultiFormGroup(
                  title: 'Grant Types',
                  value: client.grantTypes,
                  isEditing: _isEditing,
                  onChanged: (List<String> grantTypes) {
                    cubit.updateFormState(grantTypes: grantTypes);
                  },
                ),
                FormGroup(
                  title: 'Json Web Key Set (JWKS) URI',
                  value: client.jwksUri,
                  isEditing: _isEditing,
                  onChanged: (String jwksUri) {
                    cubit.updateFormState(jwksUri: jwksUri);
                  },
                ),
                FormGroup(
                  title: 'Logo URI',
                  value: client.logoUri,
                  isEditing: _isEditing,
                  onChanged: (String logoUri) {
                    cubit.updateFormState(logoUri: logoUri);
                  },
                ),
              ].spacedByAll(const [
                SizedBox(height: 5),
                Divider(),
                SizedBox(height: 5),
              ]),
            ),
          );
        }

        return Scaffold(
          appBar: AppBar(
            title: Text(title),
            actions: _isEditing
                ? [
                    IconButton(
                      icon: Icon(Icons.check),
                      onPressed: () => setState(() => _isEditing = false),
                    ),
                  ]
                : [
                    IconButton(
                      icon: Icon(Icons.edit),
                      onPressed: () => setState(() => _isEditing = true),
                    ),
                  ],
          ),
          body: body,
        );
      },
    );
  }
}

class MultiFormGroup<T> extends FormGroup<List<T>> {
  MultiFormGroup({
    String title,
    List<T> value,
    ValueChanged<List<T>> onChanged,
    bool isEditing,
    Widget child,
    Widget headerButton,
  }) : super(
          title: title,
          value: value,
          onChanged: onChanged,
          isEditing: isEditing,
          child: child,
          headerButton: headerButton,
        );

  @override
  Widget get formField {
    switch (T) {
      case String:
        return Column(
          children: [
            for (var i = 0; i < value.length; i++)
              TextFormField(
                initialValue: value[i].toString(),
                onChanged: (String val) {
                  (onChanged as ValueChanged<List>)(
                    [
                      ...value.sublist(0, i),
                      val,
                      ...value.sublist(i + 1),
                    ],
                  );
                },
              )
          ],
        );
    }
  }
}

class FormGroup<T> extends StatelessWidget {
  final String title;
  final T value;
  final ValueChanged<T> onChanged;
  final bool isEditing;
  final Widget headerButton;
  final Widget child;

  FormGroup({
    this.title,
    this.value,
    this.onChanged,
    this.isEditing,
    this.headerButton,
    this.child,
  });

  Widget get formField {
    switch (T) {
      case String:
        return TextFormField(
          initialValue: value as String,
          onChanged: onChanged as ValueChanged<String>,
        );
      case num:
        return TextFormField(
          initialValue: value.toString(),
          onChanged: (String val) {
            (onChanged as ValueChanged<num>)(num.tryParse(val));
          },
        );
    }

    return null;
  }

  @override
  Widget build(BuildContext context) {
    final headerStyle = Theme.of(context).textTheme.headline6;
    final bodyStyle = Theme.of(context).textTheme.bodyText2;

    final header = Container(
      width: 200,
      child: Row(
        children: [
          Expanded(child: Text(title, style: headerStyle)),
          if (isEditing && headerButton != null) headerButton,
        ],
      ),
    );
    Widget _child;
    if (isEditing) {
      _child = formField;
    } else {
      _child = Text(value.toString(), style: bodyStyle);
    }
    return Row(
      children: [
        header,
        const SizedBox(width: 10),
        Expanded(child: child ?? _child),
      ],
    );
  }
}

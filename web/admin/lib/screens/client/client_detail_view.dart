import 'package:admin/bloc/client/client_cubit.dart';
import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:ftauth/ftauth.dart';
import 'package:admin/util/list.dart';
import 'package:provider/provider.dart';

class ClientDetailView extends StatefulWidget {
  @override
  _ClientDetailViewState createState() => _ClientDetailViewState();
}

class _ClientDetailViewState extends State<ClientDetailView> {
  bool _isEditing = false;
  bool _showSecret = false;

  final _formKey = GlobalKey<FormState>();

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
            child: Form(
              key: _formKey,
              child: ListView(
                children: <Widget>[
                  FormGroup<String>(
                    title: 'Client Name',
                    value: client.clientName,
                    isEditing: _isEditing,
                    onChanged: (String name) {
                      cubit.updateFormState(clientName: name);
                    },
                  ),
                  FormGroup<String>(
                    title: 'Client ID',
                    value: client.clientId,
                    isEditing: false,
                    onChanged: print,
                  ),
                  FormGroup<String>(
                    title: 'Client Type',
                    value: client.clientType.stringify,
                    isEditing: false,
                  ),
                  if (client.clientType == ClientType.confidential)
                    FormGroup<String>(
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
                                if (client.clientSecretExpiresAt != null) ...[
                                  const SizedBox(height: 5),
                                  SelectableText(
                                    client.clientSecretExpiresAt.toIso8601String(),
                                  ),
                                ],
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
                  MultiTextFormGroup(
                    title: 'Redirect URIs',
                    value: client.redirectUris,
                    isEditing: _isEditing,
                    onChanged: (List<String> redirectUris) {
                      cubit.updateFormState(redirectUris: redirectUris);
                    },
                    onAdd: () {
                      cubit.updateFormState(
                        redirectUris: [...client.redirectUris, ''],
                      );
                    },
                  ),
                  MultiTextFormGroup(
                    title: 'Scopes',
                    value: client.scopes,
                    isEditing: _isEditing,
                    onChanged: (List<String> scopes) {
                      cubit.updateFormState(scopes: scopes);
                    },
                    onAdd: () {
                      cubit.updateFormState(
                        scopes: [...client.scopes, ''],
                      );
                    },
                  ),
                  MultiTextFormGroup(
                    title: 'Grant Types',
                    value: client.grantTypes,
                    isEditing: false,
                  ),
                  FormGroup<String>(
                    title: 'Json Web Key Set (JWKS) URI',
                    value: client.jwksUri,
                    isEditing: _isEditing,
                    onChanged: (String jwksUri) {
                      cubit.updateFormState(jwksUri: jwksUri);
                    },
                  ),
                  FormGroup<String>(
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
                      onPressed: _validateAndSave,
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

  void _validateAndSave() {
    if (!_formKey.currentState.validate()) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(
        content: Text('Please fix errors in the form'),
        backgroundColor: Colors.red[300],
      ));
    }
    setState(() => _isEditing = false);
  }
}

class MultiTextFormGroup extends FormGroup<List<String>> {
  final VoidCallback onAdd;
  final ValueChanged<String> onRemove;

  MultiTextFormGroup({
    String title,
    List<String> value,
    ValueChanged<List<String>> onChanged,
    String Function(String) validator,
    this.onAdd,
    this.onRemove,
    bool isEditing,
    Widget child,
  }) : super(
          title: title,
          value: value,
          onChanged: onChanged,
          isEditing: isEditing,
          child: child,
          validator: validator,
        );

  @override
  Widget get headerButton => IconButton(
        icon: Icon(Icons.add_circle_outline),
        onPressed: onAdd,
      );

  @override
  Widget get formField {
    return Column(
      children: [
        for (var i = 0; i < value.length; i++)
          TextFormField(
            initialValue: value[i].toString(),
            onChanged: (String val) {
              onChanged(
                [
                  ...value.sublist(0, i),
                  val,
                  ...value.sublist(i + 1),
                ],
              );
            },
            validator: validator,
          )
      ],
    );
  }

  @override
  Widget staticView(BuildContext context) {
    return Column(
      mainAxisAlignment: MainAxisAlignment.start,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: <Widget>[
        for (var el in value) Text('\u00B7 $el'),
      ].spacedBy(const SizedBox(height: 5)),
    );
  }
}

class FormGroup<T> extends StatelessWidget {
  final String title;
  final T value;
  final ValueChanged<T> onChanged;
  final bool isEditing;
  final Widget child;
  final String Function(String) validator;

  FormGroup({
    this.title,
    this.value,
    this.onChanged,
    this.isEditing,
    Widget headerButton,
    this.child,
    this.validator,
  }) : _headerButton = headerButton;

  final Widget _headerButton;
  Widget get headerButton => _headerButton;

  Widget get formField {
    switch (T) {
      case String:
        return TextFormField(
          initialValue: value as String,
          onChanged: onChanged as ValueChanged<String>,
          validator: validator,
        );
      case num:
        return TextFormField(
          initialValue: value.toString(),
          onChanged: (String val) {
            (onChanged as ValueChanged<num>)(num.tryParse(val));
          },
          validator: validator,
        );
    }

    return null;
  }

  Widget staticView(BuildContext context) {
    final bodyStyle = Theme.of(context).textTheme.bodyText2;
    return Text(value.toString(), style: bodyStyle);
  }

  @override
  Widget build(BuildContext context) {
    final headerStyle = Theme.of(context).textTheme.headline6;

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
      _child = staticView(context);
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

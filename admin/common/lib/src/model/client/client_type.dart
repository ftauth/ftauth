enum ClientType { public, confidential }

extension ClientTypeX on ClientType {
  String get stringify => toString().split('.')[1];

  String get description {
    switch (this) {
      case ClientType.public:
        return 'A public client cannot keep a secret. Common examples are web '
            'and native applications. Public clients are only issued a client ID '
            'which is not private, meaning anyone with the client ID can act as '
            'that client. Trust is established through pre-defined redirect URIs, and '
            'a mechanism called DPoP (Demonstration of Proof of Possession) ensures '
            'that Man-In-The-Middle attacks are unsuccessful.\n\n'
            'These clients are required to use the authorization code grant type.';
      case ClientType.confidential:
        return 'A confidential client is able to maintain a secret. This typically '
            'refers to a server acting on behalf of a resource owner. Confidential '
            'clients are issued client secrets and use the client credentials grant type.';
    }
  }
}

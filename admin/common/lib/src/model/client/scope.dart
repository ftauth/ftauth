import 'package:json_annotation/json_annotation.dart';

part 'scope.g.dart';

@JsonSerializable()
class Scope {
  final String name;
  final String ruleset;

  Scope(this.name, this.ruleset);

  factory Scope.fromJson(Map<String, dynamic> json) => _$ScopeFromJson(json);
}

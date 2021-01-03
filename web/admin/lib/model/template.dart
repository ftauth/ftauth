enum Templates { login, register }

extension TemplatesX on Templates {
  String stringify() => toString().split('.')[1];
}

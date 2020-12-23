class ApiException implements Exception {
  final String method;
  final String path;
  final int statusCode;
  final String body;

  const ApiException(this.method, this.path, this.statusCode, [this.body = '']);

  ApiException.get(this.path, this.statusCode, [this.body = ''])
      : method = 'GET';

  ApiException.post(this.path, this.statusCode, [this.body = ''])
      : method = 'POST';

  ApiException.put(this.path, this.statusCode, [this.body = ''])
      : method = 'PUT';

  ApiException.delete(this.path, this.statusCode, [this.body = ''])
      : method = 'DELETE';

  @override
  String toString() {
    return "$method $path: $statusCode - '$body'";
  }
}

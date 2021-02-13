import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_static/shelf_static.dart';

Future<void> main() async {
  final handler = const Pipeline()
      .addMiddleware(_corsHeadersMiddleware)
      .addMiddleware(logRequests())
      .addHandler(createStaticHandler('build', defaultDocument: 'index.html'));

  final server = await io.serve(handler, 'localhost', 8000);

  print('Serving at http://${server.address.host}:${server.port}');
}

const _corsHeaders = <String, String>{'Access-Control-Allow-Origin': '*'};

Handler _corsHeadersMiddleware(Handler innerHandler) => (request) async {
      if (request.method == 'OPTIONS') {
        return Response.ok(null, headers: _corsHeaders);
      }

      final response = await innerHandler(request);

      return response.change(headers: _corsHeaders);
    };

import 'dart:convert';

Map<String, dynamic> decodeJSON(String json) {
  return (jsonDecode(json) as Map).cast<String, dynamic>();
}

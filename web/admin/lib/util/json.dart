import 'dart:convert';

Map<String, dynamic> decodeJSON(String json) {
  return (jsonDecode(json) as Map).cast<String, dynamic>();
}

List<Map<String, dynamic>> decodeJSONArray(String json) {
  return (jsonDecode(json) as List).cast<Map<String, dynamic>>();
}

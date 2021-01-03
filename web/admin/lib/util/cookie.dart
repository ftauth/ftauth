class CookieUtil {
  static Map<String, String> parseCookies(String cookieString) {
    final ret = <String, String>{};
    final cookieStrings = cookieString.split(';');
    for (final cookie in cookieStrings) {
      final parsedCookie = cookie.split('=');
      if (parsedCookie.length == 2) {
        ret[parsedCookie[0].trim()] = parsedCookie[1].trim();
      }
    }
    return ret;
  }
}

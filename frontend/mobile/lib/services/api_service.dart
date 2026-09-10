import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import '../models/alert.dart';

class ApiService {
  ApiService({String? baseUrl})
      : baseUrl = baseUrl ??
            const String.fromEnvironment('API_BASE',
                defaultValue: 'http://10.0.2.2:8090');

  final String baseUrl;
  String? _token;

  Future<void> _loadToken() async {
    _token ??= (await SharedPreferences.getInstance()).getString('cg_token');
  }

  Future<Map<String, String>> _headers() async {
    await _loadToken();
    return {
      'Content-Type': 'application/json',
      if (_token != null) 'Authorization': 'Bearer $_token',
    };
  }

  Future<bool> login(String email, String password) async {
    final res = await http.post(
      Uri.parse('$baseUrl/api/auth/login'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'email': email, 'password': password}),
    );
    if (res.statusCode != 200) return false;
    _token = jsonDecode(res.body)['access_token'] as String;
    (await SharedPreferences.getInstance()).setString('cg_token', _token!);
    return true;
  }

  Future<RiskSnapshot> riskDashboard() async {
    final res = await http.get(
      Uri.parse('$baseUrl/api/risk-score/dashboard'),
      headers: await _headers(),
    );
    return RiskSnapshot.fromJson(jsonDecode(res.body));
  }

  Future<List<SecurityAlert>> alerts() async {
    final res = await http.get(
      Uri.parse('$baseUrl/api/alerts'),
      headers: await _headers(),
    );
    final data = jsonDecode(res.body)['alerts'] as List;
    return data.map((e) => SecurityAlert.fromJson(e)).toList();
  }

  Future<void> acknowledge(String id) async {
    await http.put(
      Uri.parse('$baseUrl/api/alerts/$id/acknowledge'),
      headers: await _headers(),
    );
  }

  Future<Map<String, dynamic>> quickScan() async {
    final res = await http.post(
      Uri.parse('$baseUrl/api/security-debt/scan'),
      headers: await _headers(),
      body: jsonEncode({}),
    );
    return jsonDecode(res.body) as Map<String, dynamic>;
  }
}

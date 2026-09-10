import 'package:flutter/material.dart';
import '../services/api_service.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key, required this.api});
  final ApiService api;

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  final _email = TextEditingController(text: 'admin@cyberguard.ai');
  final _password = TextEditingController(text: 'cyberguard-demo');
  bool _pushEnabled = true;
  String _status = '';

  Future<void> _login() async {
    final ok = await widget.api.login(_email.text, _password.text);
    setState(() => _status = ok ? 'Signed in' : 'Login failed');
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Settings')),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          TextField(
            controller: _email,
            decoration: const InputDecoration(labelText: 'Email'),
          ),
          TextField(
            controller: _password,
            obscureText: true,
            decoration: const InputDecoration(labelText: 'Password'),
          ),
          const SizedBox(height: 12),
          FilledButton(onPressed: _login, child: const Text('Sign in')),
          if (_status.isNotEmpty) Padding(
            padding: const EdgeInsets.only(top: 8),
            child: Text(_status),
          ),
          const Divider(height: 32),
          SwitchListTile(
            title: const Text('Push notifications for alerts'),
            value: _pushEnabled,
            onChanged: (v) => setState(() => _pushEnabled = v),
          ),
          const ListTile(
            title: Text('API base URL'),
            subtitle: Text('Set via --dart-define=API_BASE=...'),
          ),
          const AboutListTile(
            applicationName: 'CyberGuard AI',
            applicationVersion: '0.1.0',
          ),
        ],
      ),
    );
  }
}

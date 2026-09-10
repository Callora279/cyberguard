import 'package:flutter/material.dart';
import '../models/alert.dart';
import '../services/api_service.dart';

class AlertsScreen extends StatefulWidget {
  const AlertsScreen({super.key, required this.api});
  final ApiService api;

  @override
  State<AlertsScreen> createState() => _AlertsScreenState();
}

class _AlertsScreenState extends State<AlertsScreen> {
  List<SecurityAlert> _alerts = [];
  bool _loading = true;

  static const _sevColor = {
    'critical': Colors.red,
    'high': Colors.orange,
    'medium': Colors.amber,
    'low': Colors.green,
    'info': Colors.blueGrey,
  };

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    try {
      _alerts = await widget.api.alerts();
    } finally {
      setState(() => _loading = false);
    }
  }

  Future<void> _ack(SecurityAlert a) async {
    await widget.api.acknowledge(a.id);
    await _load();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Alerts')),
      body: RefreshIndicator(
        onRefresh: _load,
        child: _loading
            ? const Center(child: CircularProgressIndicator())
            : ListView.builder(
                itemCount: _alerts.length,
                itemBuilder: (_, i) {
                  final a = _alerts[i];
                  return ListTile(
                    leading: CircleAvatar(
                      backgroundColor:
                          _sevColor[a.severity] ?? Colors.blueGrey,
                      radius: 6,
                    ),
                    title: Text(a.title),
                    subtitle: Text('${a.module} · ${a.severity}'),
                    trailing: a.acknowledged
                        ? const Icon(Icons.check, color: Colors.green)
                        : TextButton(
                            onPressed: () => _ack(a), child: const Text('ACK')),
                  );
                },
              ),
      ),
    );
  }
}

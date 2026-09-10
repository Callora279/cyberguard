import 'package:flutter/material.dart';
import '../models/alert.dart';
import '../services/api_service.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key, required this.api});
  final ApiService api;

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  RiskSnapshot? _snap;
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    try {
      final snap = await widget.api.riskDashboard();
      setState(() {
        _snap = snap;
        _error = null;
      });
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      setState(() => _loading = false);
    }
  }

  Future<void> _quickScan() async {
    ScaffoldMessenger.of(context)
        .showSnackBar(const SnackBar(content: Text('Running scan…')));
    await widget.api.quickScan();
    await _load();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('CyberGuard AI')),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _quickScan,
        icon: const Icon(Icons.radar),
        label: const Text('Quick Scan'),
      ),
      body: RefreshIndicator(
        onRefresh: _load,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            if (_loading) const LinearProgressIndicator(),
            if (_error != null)
              Card(
                color: Colors.red.shade900,
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Text('Error: $_error'),
                ),
              ),
            if (_snap != null) ...[
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(24),
                  child: Column(
                    children: [
                      const Text('Unified Risk Score'),
                      const SizedBox(height: 8),
                      Text('${_snap!.score.toStringAsFixed(0)}',
                          style: const TextStyle(
                              fontSize: 56, fontWeight: FontWeight.bold)),
                      Chip(label: Text('Grade ${_snap!.grade}')),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 12),
              ..._snap!.breakdown.entries.map((e) => Card(
                    child: ListTile(
                      title: Text(e.key.replaceAll('_', ' ')),
                      trailing: Text('${(e.value as num).toStringAsFixed(0)}'),
                    ),
                  )),
            ],
          ],
        ),
      ),
    );
  }
}

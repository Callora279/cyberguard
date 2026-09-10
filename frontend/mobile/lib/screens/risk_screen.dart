import 'package:flutter/material.dart';
import 'package:fl_chart/fl_chart.dart';
import '../models/alert.dart';
import '../services/api_service.dart';

class RiskScreen extends StatefulWidget {
  const RiskScreen({super.key, required this.api});
  final ApiService api;

  @override
  State<RiskScreen> createState() => _RiskScreenState();
}

class _RiskScreenState extends State<RiskScreen> {
  RiskSnapshot? _snap;

  @override
  void initState() {
    super.initState();
    widget.api.riskDashboard().then((s) => setState(() => _snap = s));
  }

  @override
  Widget build(BuildContext context) {
    final trend = _snap?.trend ?? [];
    final spots = <FlSpot>[
      for (var i = 0; i < trend.length; i++)
        FlSpot(i.toDouble(), (trend[i]['score'] as num).toDouble()),
    ];

    return Scaffold(
      appBar: AppBar(title: const Text('Risk Trend')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: _snap == null
            ? const Center(child: CircularProgressIndicator())
            : Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Current: ${_snap!.score.toStringAsFixed(0)} (${_snap!.grade})',
                      style: Theme.of(context).textTheme.titleLarge),
                  const SizedBox(height: 24),
                  Expanded(
                    child: spots.length < 2
                        ? const Center(child: Text('Not enough history yet'))
                        : LineChart(
                            LineChartData(
                              minY: 0,
                              maxY: 100,
                              lineBarsData: [
                                LineChartBarData(
                                  spots: spots,
                                  isCurved: true,
                                  color: const Color(0xFF4F8CFF),
                                  dotData: const FlDotData(show: false),
                                ),
                              ],
                            ),
                          ),
                  ),
                ],
              ),
      ),
    );
  }
}

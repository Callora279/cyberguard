class SecurityAlert {
  final String id;
  final String module;
  final String severity;
  final String title;
  final String body;
  final bool acknowledged;
  final DateTime createdAt;

  SecurityAlert({
    required this.id,
    required this.module,
    required this.severity,
    required this.title,
    required this.body,
    required this.acknowledged,
    required this.createdAt,
  });

  factory SecurityAlert.fromJson(Map<String, dynamic> json) => SecurityAlert(
        id: json['id'] as String,
        module: json['module'] as String? ?? 'unknown',
        severity: json['severity'] as String? ?? 'info',
        title: json['title'] as String? ?? '',
        body: json['body'] as String? ?? '',
        acknowledged: json['acknowledged'] as bool? ?? false,
        createdAt: DateTime.tryParse(json['created_at']?.toString() ?? '') ??
            DateTime.now(),
      );
}

class RiskSnapshot {
  final double score;
  final String grade;
  final Map<String, dynamic> breakdown;
  final List<Map<String, dynamic>> trend;

  RiskSnapshot({
    required this.score,
    required this.grade,
    required this.breakdown,
    required this.trend,
  });

  factory RiskSnapshot.fromJson(Map<String, dynamic> json) => RiskSnapshot(
        score: (json['score'] ?? 0).toDouble(),
        grade: json['grade']?.toString() ?? '?',
        breakdown: Map<String, dynamic>.from(json['breakdown'] ?? {}),
        trend: List<Map<String, dynamic>>.from(
            (json['trend_30d'] ?? []).map((e) => Map<String, dynamic>.from(e))),
      );
}

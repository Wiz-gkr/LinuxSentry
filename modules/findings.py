class Finding:
    def __init__(
        self,
        severity,
        category,
        message,
        recommendation="",
        confidence="MEDIUM"
    ):
        self.severity = severity.upper()
        self.category = category
        self.message = message
        self.recommendation = recommendation
        self.confidence = confidence.upper()

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "recommendation": self.recommendation,
            "confidence": self.confidence,
        }

    def __str__(self):
        return (
            f"[{self.severity}] {self.category}\n"
            f"  Finding      : {self.message}\n"
            f"  Confidence   : {self.confidence}\n"
            f"  Recommendation: {self.recommendation}"
        )

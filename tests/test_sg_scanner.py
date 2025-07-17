import pytest
from unittest.mock import patch, MagicMock

def test_sg_scanner_integration_with_mocks():
    mock_groups = [MagicMock(group_id="sg-1"), MagicMock(group_id="sg-2")]
    mock_findings = [
        {"group_id": "sg-1", "type": "open_port", "raw_data": {"cidr": "0.0.0.0/0"}},
        {"group_id": "sg-2", "type": "cross_account", "raw_data": {"user_id": "2222"}}
    ]
    with patch("aws_scanner.scanners.sg.collector.collect_security_groups", return_value=mock_groups) as mock_collect, \
         patch("aws_scanner.scanners.sg.analyzer.analyze_sg", side_effect=lambda sg: [f for f in mock_findings if f["group_id"] == sg.group_id]) as mock_analyze:
        from aws_scanner.scanners.sg.collector import collect_security_groups
        from aws_scanner.scanners.sg.analyzer import analyze_sg
        groups = collect_security_groups(MagicMock())
        findings = []
        for sg in groups:
            findings.extend(analyze_sg(sg))
        assert any(f["type"] == "open_port" and f["raw_data"]["cidr"] == "0.0.0.0/0" for f in findings)
        assert any(f["type"] == "cross_account" and f["raw_data"]["user_id"] == "2222" for f in findings)
        assert mock_collect.called
        assert mock_analyze.call_count == len(mock_groups)

import json
from unittest import mock
from aws_scanner.cli.main import main


def test_main_catches_unexpected_exception(capsys):
    with mock.patch('aws_scanner.cli.main.get_args') as mock_get_args, \
         mock.patch('aws_scanner.cli.main.create_run_config') as mock_create_config, \
         mock.patch('aws_scanner.cli.main.run_scan') as mock_run_scan:

        mock_get_args.return_value = mock.Mock()
        mock_create_config.return_value = mock.Mock()
        mock_run_scan.side_effect = ZeroDivisionError("Unexpected internal error")

        with mock.patch('sys.exit') as mock_exit:
            main()

        captured = capsys.readouterr()

        assert mock_exit.called
        exit_code = mock_exit.call_args[0][0]
        assert exit_code == 0, f"Expected exit code 0, got {exit_code}"

        output = json.loads(captured.out)

        assert "errors" in output or "iam_roles" in output, "Expected valid JSON output structure"

        assert "Traceback" not in captured.out, "Stack trace should not appear in stdout"
        assert "Traceback" not in captured.err, "Stack trace should not appear in stderr"

"""
Tests for port validation in CLI.

"Even the very wise cannot see all ends, but tests help prevent unfortunate ones."
"""

import pytest
import typer
from typer.testing import CliRunner

from staff.cli import app, validate_port_spec


runner = CliRunner()


class TestValidatePortSpec:
    """Tests for validate_port_spec function."""

    def test_valid_single_port(self):
        """Valid single port should not raise."""
        # Should not raise any exception
        validate_port_spec("22")
        validate_port_spec("80")
        validate_port_spec("443")
        validate_port_spec("8080")

    def test_valid_comma_separated_ports(self):
        """Valid comma-separated ports should not raise."""
        validate_port_spec("22,80,443")
        validate_port_spec("80, 443, 8080")

    def test_valid_port_range(self):
        """Valid port range should not raise."""
        validate_port_spec("1-1000")
        validate_port_spec("80-443")
        validate_port_spec("1-65535")

    def test_valid_mixed_format(self):
        """Valid mixed format should not raise."""
        validate_port_spec("22,80,443,8000-9000")

    def test_invalid_port_zero(self):
        """Port 0 should raise typer.Exit."""
        with pytest.raises(SystemExit):
            validate_port_spec("0")

    def test_invalid_port_out_of_range(self):
        """Port > 65535 should raise typer.Exit."""
        with pytest.raises(SystemExit):
            validate_port_spec("65536")

    def test_invalid_port_non_numeric(self):
        """Non-numeric port should raise typer.Exit."""
        with pytest.raises(SystemExit):
            validate_port_spec("abc")

    def test_invalid_port_negative(self):
        """Negative numbers in range should raise typer.Exit."""
        with pytest.raises(SystemExit):
            validate_port_spec("-1")

    def test_invalid_range_non_numeric(self):
        """Non-numeric in range should raise typer.Exit."""
        with pytest.raises(SystemExit):
            validate_port_spec("1-abc")

    def test_invalid_range_reversed(self):
        """Range with start > end should raise typer.Exit."""
        with pytest.raises(SystemExit):
            validate_port_spec("1000-500")


class TestDelveCommandValidation:
    """Integration tests for delve command port validation."""

    def test_delve_invalid_port_zero(self):
        """Delve with port 0 should show error message."""
        result = runner.invoke(app, ["delve", "localhost", "-p", "0"])
        assert result.exit_code == 1
        assert "Invalid port" in result.output or "Port numbers must be at least 1" in result.output

    def test_delve_invalid_port_out_of_range(self):
        """Delve with port 65536 should show error message."""
        result = runner.invoke(app, ["delve", "localhost", "-p", "65536"])
        assert result.exit_code == 1
        assert "out of range" in result.output or "65535" in result.output

    def test_delve_invalid_port_non_numeric(self):
        """Delve with non-numeric port should show error message."""
        result = runner.invoke(app, ["delve", "localhost", "-p", "abc"])
        assert result.exit_code == 1
        assert "Non-numeric" in result.output or "numbers" in result.output

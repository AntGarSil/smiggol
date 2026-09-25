"""Validation gates for generated WAF rules and their compiled Terraform."""
from waf_factory.validation.rules import validate_rules
from waf_factory.validation.terraform_syntax import run_syntax_gate

__all__ = ["validate_rules", "run_syntax_gate"]

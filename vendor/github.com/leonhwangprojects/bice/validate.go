// SPDX-License-Identifier: Apache-2.0
/* Copyright Leon Hwang */

package bice

import (
	"fmt"

	"rsc.io/c2go/cc"
)

func validateOperator(op cc.ExprOp) error {
	switch op {
	case cc.Eq, cc.EqEq, cc.NotEq, cc.Lt, cc.LtEq, cc.Gt, cc.GtEq:
		return nil
	default:
		return fmt.Errorf("unexpected operator: %s; must be one of =, ==, !=, <, <=, >, >=", op)
	}
}

// validateLeftOperand checks if the left operand is struct member access like:
// [[skb] -> dev] -> ifindex
func validateLeftOperand(left *cc.Expr) error {
	if left == nil {
		return nil
	}

	if left.Left == nil && left.Right == nil {
		return nil
	}

	if left.Right != nil {
		return fmt.Errorf("left operand must be struct member access")
	}

	if left.Op != cc.Dot && left.Op != cc.Arrow {
		return fmt.Errorf("unexpected left operand: %v; must be struct member access", left)
	}

	return validateLeftOperand(left.Left)
}

func validateRightOperand(right *cc.Expr) error {
	if right.Op != cc.Number && right.Op != cc.Name {
		return fmt.Errorf("expect constant number or enum as right operand, got %s", right.Text)
	}

	if right.Op == cc.Name {
		return nil
	}

	if _, err := parseNumber(right.Text); err != nil {
		return fmt.Errorf("right operand is not a number: %w", err)
	}

	return nil
}

// validate checks if the expression is expected simple C expression by
// checking:
// 1. The top level operator is one of the following: =, ==, !=, <, <=, >, >=
// 2. The left operand is struct member access
// 3. The right operand is a constant number in hex, octal, or decimal format
func validate(expr *cc.Expr) error {
	if err := validateOperator(expr.Op); err != nil {
		return err
	}

	if expr.Left == nil {
		return fmt.Errorf("left operand is missing")
	}
	if err := validateLeftOperand(expr.Left); err != nil {
		return err
	}

	if expr.Right == nil {
		return fmt.Errorf("right operand is missing")
	}
	if err := validateRightOperand(expr.Right); err != nil {
		return err
	}

	return nil
}

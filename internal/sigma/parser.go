package sigma

import (
	"fmt"
	"strings"

	"github.com/atontalapur/signalman/internal/sigma/ast"
)

// maxDepth bounds nesting of parentheses and not so that a hostile
// condition cannot overflow the stack.
const maxDepth = 100

type parser struct {
	toks  []token
	i     int
	depth int
}

// ParseCondition parses a Sigma condition string. The result contains Ident
// and Quant leaves; expansion and binding replace them.
func ParseCondition(s string) (ast.Node, error) {
	toks, err := lex(s)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("unexpected %s at offset %d", p.peek().kind, p.peek().pos)
	}
	return n, nil
}

func (p *parser) peek() token { return p.toks[p.i] }

func (p *parser) next() token {
	t := p.toks[p.i]
	if t.kind != tokEOF {
		p.i++
	}
	return t
}

func (p *parser) enter() error {
	p.depth++
	if p.depth > maxDepth {
		return fmt.Errorf("condition nests deeper than %d levels", maxDepth)
	}
	return nil
}

func (p *parser) leave() { p.depth-- }

// Precedence is not > and > or, so parseOr sits on top and each level
// delegates to the tighter one below it.
func (p *parser) parseOr() (ast.Node, error) {
	first, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	kids := []ast.Node{first}
	for p.peek().kind == tokOr {
		p.next()
		n, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		kids = append(kids, n)
	}
	if len(kids) == 1 {
		return first, nil
	}
	return &ast.Or{Children: kids}, nil
}

func (p *parser) parseAnd() (ast.Node, error) {
	first, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	kids := []ast.Node{first}
	for p.peek().kind == tokAnd {
		p.next()
		n, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		kids = append(kids, n)
	}
	if len(kids) == 1 {
		return first, nil
	}
	return &ast.And{Children: kids}, nil
}

func (p *parser) parseNot() (ast.Node, error) {
	if p.peek().kind == tokNot {
		p.next()
		if err := p.enter(); err != nil {
			return nil, err
		}
		defer p.leave()
		child, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &ast.Not{Child: child}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (ast.Node, error) {
	t := p.peek()
	switch t.kind {
	case tokLParen:
		p.next()
		if err := p.enter(); err != nil {
			return nil, err
		}
		defer p.leave()
		n, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokRParen {
			return nil, fmt.Errorf("missing ) at offset %d", p.peek().pos)
		}
		p.next()
		return n, nil
	case tokIdent:
		p.next()
		if p.peek().kind == tokOf {
			return p.parseQuant(t)
		}
		return &ast.Ident{Name: t.text}, nil
	default:
		return nil, fmt.Errorf("unexpected %s at offset %d", t.kind, t.pos)
	}
}

// parseQuant handles "1 of x", "any of x", "all of x", and "... of them".
// count has already been consumed as an identifier.
func (p *parser) parseQuant(count token) (ast.Node, error) {
	var c ast.QuantCount
	switch strings.ToLower(count.text) {
	case "1", "any":
		c = ast.QuantOne
	case "all":
		c = ast.QuantAll
	default:
		return nil, fmt.Errorf("unsupported quantifier %q at offset %d: only 1, any, and all are defined", count.text, count.pos)
	}
	p.next() // consume "of"
	target := p.peek()
	if target.kind != tokIdent {
		return nil, fmt.Errorf("expected a selection pattern or 'them' after 'of' at offset %d", target.pos)
	}
	p.next()
	if strings.EqualFold(target.text, "them") {
		return &ast.Quant{Count: c, Them: true}, nil
	}
	return &ast.Quant{Count: c, Pattern: target.text}, nil
}

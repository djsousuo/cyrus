package models

func NewStack() *Stack {
	return &Stack{}
}

type Stack []string

func (s *Stack) Push(str string) {
	*s = append(*s, str)
}

func (s *Stack) Pop() string {
	n := len(*s)
	if n == 0 {
		return ""
	}
	old := *s
	x := old[n-1]
	*s = old[0 : n-1]
	return x
}

func (s Stack) Peek() string {
	l := len(s)
	if l == 0 {
		return ""
	}
	return s[l-1]
}

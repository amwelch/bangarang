package alarm

import (
	"log"
	"reflect"
	"regexp"
	"strings"

	"github.com/eliothedeman/bangarang/event"
)

func init() {
	log.SetFlags(log.Llongfile)
}

type Escalation struct {
	Policy           Policy  `json:"policy"`
}

func (e *Escalation) Match(ev *event.Event) bool {
	return e.Policy.CheckMatch(ev) && e.Policy.CheckNotMatch(ev)
}

func (e *Escalation) StatusOf(ev *event.Event) int {
	return e.Policy.StatusOf(ev)
}

type Policy struct {
	Match       map[string]string `json:"match"`
	NotMatch    map[string]string `json:"not_match"`
	Crit        *Condition        `json:"crit"`
	Warn        *Condition        `json:"warn"`
	r_match     map[string]*regexp.Regexp
	r_not_match map[string]*regexp.Regexp
}

func (p *Policy) LoadAlarms() error {
	err := p.Crit.LoadAlarms()
	if err != nil{
		return err
	}
	err = p.Warn.LoadAlarms()
	if err != nil{
		return err
	}
	return nil
}

// compile the regex patterns for this policy
func (p *Policy) Compile() {
	if p.r_match == nil {
		p.r_match = make(map[string]*regexp.Regexp)
	}

	if p.r_not_match == nil {
		p.r_not_match = make(map[string]*regexp.Regexp)
	}

	for k, v := range p.Match {
		p.r_match[k] = regexp.MustCompile(v)
	}

	for k, v := range p.NotMatch {
		p.r_not_match[k] = regexp.MustCompile(v)
	}
}

func formatFileName(n string) string {
	s := strings.Split(n, "_")
	a := ""
	for _, k := range s {
		a = a + strings.Title(k)
	}
	return a
}

func (p *Policy) StatusOf(e *event.Event) int {
	if p.Crit != nil {
		if p.Crit.TrackEvent(e) {
			e.Status = event.CRITICAL
			return event.CRITICAL
		}
		p.Crit.CleanEvent(e)
	}
	if p.Warn != nil {
		if p.Warn.TrackEvent(e) {
			e.Status = event.WARNING
			return event.WARNING
		}
		p.Warn.CleanEvent(e)
	}

	e.Status = event.OK
	return event.OK
}

func (p *Policy) GetEscalationPolicy(e *event.Event) string {
	if e.Status == event.CRITICAL {
		if p.Crit != nil {
			return p.Crit.EscalationPolicy
		} else {
			return ""
		}
	} else if e.Status == event.WARNING {
		if p.Warn != nil {
			return p.Warn.EscalationPolicy
		} else {
			return ""
		}
	}
	return ""
}

func (p *Policy) GetAlarms(e *event.Event) []Alarm {
	if e.Status == event.CRITICAL {
		if p.Crit != nil {
			return p.Crit.Alarms
		}
	} else if e.Status == event.WARNING {
		if p.Warn != nil {
			return p.Warn.Alarms
		}
	}
	return []Alarm{}
}


func (p *Policy) CheckNotMatch(e *event.Event) bool {
	v := reflect.ValueOf(e).Elem()
	for k, m := range p.r_not_match {
		elem := v.FieldByName(formatFileName(k))
		if m.MatchString(elem.String()) {
			return false

			// check againt the element's tags
			if e.Tags != nil {
				if against, inMap := e.Tags[k]; inMap {
					if m.MatchString(against) {
						return false
					}
				}
			}
		}
	}

	return true
}

// check if any of p's matches are satisfied by the event
func (p *Policy) CheckMatch(e *event.Event) bool {
	v := reflect.ValueOf(e).Elem()
	for k, m := range p.r_match {
		elem := v.FieldByName(formatFileName(k))

		// if the element does not match the regex pattern, the event does not fully match
		if !m.MatchString(elem.String()) {

			// check againt the element's tags
			if e.Tags == nil {
				return false
			}
			if against, inMap := e.Tags[k]; inMap {
				if !m.MatchString(against) {
					return false
				}
			} else {
				return false
			}
		}
	}

	return true
}

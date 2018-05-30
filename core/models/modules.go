package models

//Module interface to be implemented by module
type Module interface {
	OnLoad(string) (ModuleInfo, error)
	Execute(<-chan Record, chan<- Record) error
}

//ModuleInfo holds information about module
type ModuleInfo struct {
	ID          string
	Name        string
	Version     string
	Author      string
	Website     string
	Description string
	Module      Module
}

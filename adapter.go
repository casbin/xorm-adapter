// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package xormadapter

import (
	"errors"
	"runtime"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/lib/pq"
	"xorm.io/xorm"
)

func (the *CasbinRule) TableName() string {
	if len(the.tableName) == 0 {
		return "casbin_rule"
	}
	return the.tableName
}

type CasbinRule struct {
	PType     string `xorm:"varchar(100) index not null default ''"`
	V0        string `xorm:"varchar(100) index not null default ''"`
	V1        string `xorm:"varchar(100) index not null default ''"`
	V2        string `xorm:"varchar(100) index not null default ''"`
	V3        string `xorm:"varchar(100) index not null default ''"`
	V4        string `xorm:"varchar(100) index not null default ''"`
	V5        string `xorm:"varchar(100) index not null default ''"`
	tableName string `xorm:"-" json:"-"`
}

// Adapter represents the Xorm adapter for policy storage.
type Adapter struct {
	driverName     string
	dataSourceName string
	dbSpecified    bool
	isFiltered     bool
	engine         *xorm.Engine
	tableName      string
}

type Filter struct {
	PType []string
	V0    []string
	V1    []string
	V2    []string
	V3    []string
	V4    []string
	V5    []string
}

// finalizer is the destructor for Adapter.
func finalizer(a *Adapter) {
	err := a.engine.Close()
	if err != nil {
		panic(err)
	}
}

// NewAdapter is the constructor for Adapter.
// dbSpecified is an optional bool parameter. The default value is false.
// It's up to whether you have specified an existing DB in dataSourceName.
// If dbSpecified == true, you need to make sure the DB in dataSourceName exists.
// If dbSpecified == false, the adapter will automatically create a DB named "casbin".
func NewAdapter(driverName string, dataSourceName string, dbSpecified ...bool) (*Adapter, error) {
	a := &Adapter{
		driverName:     driverName,
		dataSourceName: dataSourceName,
	}

	if len(dbSpecified) == 0 {
		a.dbSpecified = false
	} else if len(dbSpecified) == 1 {
		a.dbSpecified = dbSpecified[0]
	} else {
		return nil, errors.New("invalid parameter: dbSpecified")
	}

	// Open the DB, create it if not existed.
	err := a.open()
	if err != nil {
		return nil, err
	}

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a, nil
}

func NewAdapterWithTableName(driverName string, dataSourceName string, tableName string, dbSpecified ...bool) (*Adapter, error) {
	a := &Adapter{
		driverName:     driverName,
		dataSourceName: dataSourceName,
		tableName:      tableName,
	}

	if len(dbSpecified) == 0 {
		a.dbSpecified = false
	} else if len(dbSpecified) == 1 {
		a.dbSpecified = dbSpecified[0]
	} else {
		return nil, errors.New("invalid parameter: dbSpecified")
	}

	// Open the DB, create it if not existed.
	err := a.open()
	if err != nil {
		return nil, err
	}

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a, nil
}

func NewAdapterByEngine(engine *xorm.Engine) (*Adapter, error) {
	a := &Adapter{
		engine: engine,
	}

	err := a.createTable()
	if err != nil {
		return nil, err
	}

	return a, nil
}

func NewAdapterByEngineWithTableName(engine *xorm.Engine, tableName string) (*Adapter, error) {
	a := &Adapter{
		engine:    engine,
		tableName: tableName,
	}

	err := a.createTable()
	if err != nil {
		return nil, err
	}

	return a, nil
}

func (a *Adapter) createDatabase() error {
	var err error
	var engine *xorm.Engine
	if a.driverName == "postgres" {
		engine, err = xorm.NewEngine(a.driverName, a.dataSourceName+" dbname=postgres")
	} else {
		engine, err = xorm.NewEngine(a.driverName, a.dataSourceName)
	}
	if err != nil {
		return err
	}

	if a.driverName == "postgres" {
		if _, err = engine.Exec("CREATE DATABASE casbin"); err != nil {
			// 42P04 is	duplicate_database
			if pqerr, ok := err.(*pq.Error); ok && pqerr.Code == "42P04" {
				_ = engine.Close()
				return nil
			}
		}
	} else if a.driverName != "sqlite3" {
		_, err = engine.Exec("CREATE DATABASE IF NOT EXISTS casbin")
	}
	if err != nil {
		_ = engine.Close()
		return err
	}

	return engine.Close()
}

func (a *Adapter) open() error {
	var err error
	var engine *xorm.Engine

	if a.dbSpecified {
		engine, err = xorm.NewEngine(a.driverName, a.dataSourceName)
		if err != nil {
			return err
		}
	} else {
		if err = a.createDatabase(); err != nil {
			return err
		}

		if a.driverName == "postgres" {
			engine, err = xorm.NewEngine(a.driverName, a.dataSourceName+" dbname=casbin")
		} else if a.driverName == "sqlite3" {
			engine, err = xorm.NewEngine(a.driverName, a.dataSourceName)
		} else {
			engine, err = xorm.NewEngine(a.driverName, a.dataSourceName+"casbin")
		}
		if err != nil {
			return err
		}
	}

	a.engine = engine

	return a.createTable()
}

func (a *Adapter) close() error {
	err := a.engine.Close()
	if err != nil {
		return err
	}

	a.engine = nil
	return nil
}

func (a *Adapter) createTable() error {
	return a.engine.Sync2(&CasbinRule{tableName: a.tableName})
}

func (a *Adapter) dropTable() error {
	return a.engine.DropTables(&CasbinRule{tableName: a.tableName})
}

func loadPolicyLine(line *CasbinRule, model model.Model) {
	var p = []string{line.PType,
		line.V0, line.V1, line.V2, line.V3, line.V4, line.V5}
	var lineText string
	if line.V5 != "" {
		lineText = strings.Join(p, ", ")
	} else if line.V4 != "" {
		lineText = strings.Join(p[:6], ", ")
	} else if line.V3 != "" {
		lineText = strings.Join(p[:5], ", ")
	} else if line.V2 != "" {
		lineText = strings.Join(p[:4], ", ")
	} else if line.V1 != "" {
		lineText = strings.Join(p[:3], ", ")
	} else if line.V0 != "" {
		lineText = strings.Join(p[:2], ", ")
	}

	persist.LoadPolicyLine(lineText, model)
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	var lines []*CasbinRule
	if err := a.engine.Find(&lines); err != nil {
		return err
	}

	for _, line := range lines {
		loadPolicyLine(line, model)
	}

	return nil
}

func (a *Adapter) savePolicyLine(ptype string, rule []string) *CasbinRule {
	line := &CasbinRule{PType: ptype, tableName: a.tableName}

	l := len(rule)
	if l > 0 {
		line.V0 = rule[0]
	}
	if l > 1 {
		line.V1 = rule[1]
	}
	if l > 2 {
		line.V2 = rule[2]
	}
	if l > 3 {
		line.V3 = rule[3]
	}
	if l > 4 {
		line.V4 = rule[4]
	}
	if l > 5 {
		line.V5 = rule[5]
	}

	return line
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	err := a.dropTable()
	if err != nil {
		return err
	}
	err = a.createTable()
	if err != nil {
		return err
	}

	var lines []*CasbinRule

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := a.savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := a.savePolicyLine(ptype, rule)
			lines = append(lines, line)
		}
	}

	_, err = a.engine.Insert(&lines)
	return err
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	_, err := a.engine.Insert(line)
	return err
}

// AddPolicies adds multiple policy rule to the storage.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	_, err := a.engine.Transaction(func(tx *xorm.Session) (interface{}, error) {
		for _, rule := range rules {
			line := a.savePolicyLine(ptype, rule)
			_, err := tx.Insert(line)
			if err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	return err
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	_, err := a.engine.Delete(line)
	return err
}

// ReovRemovePolicies removes multiple policy rule from the storage.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	_, err := a.engine.Transaction(func(tx *xorm.Session) (interface{}, error) {
		for _, rule := range rules {
			line := a.savePolicyLine(ptype, rule)
			_, err := tx.Delete(line)
			if err != nil {
				return nil, nil
			}
		}
		return nil, nil
	})
	return err
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	line := &CasbinRule{PType: ptype, tableName: a.tableName}

	idx := fieldIndex + len(fieldValues)
	if fieldIndex <= 0 && idx > 0 {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && idx > 1 {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && idx > 2 {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && idx > 3 {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && idx > 4 {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && idx > 5 {
		line.V5 = fieldValues[5-fieldIndex]
	}

	_, err := a.engine.Delete(line)
	return err
}

// LoadFilteredPolicy loads only policy rules that match the filter.
func (a *Adapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	var lines []*CasbinRule

	filterValue, ok := filter.(Filter)
	if !ok {
		return errors.New("invalid filter type")
	}
	if err := a.filterQuery(a.engine.NewSession(), filterValue).Find(&lines); err != nil {
		return err
	}

	for _, line := range lines {
		loadPolicyLine(line, model)
	}
	a.isFiltered = true
	return nil
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *Adapter) IsFiltered() bool {
	return a.isFiltered
}

func (a *Adapter) filterQuery(session *xorm.Session, filter Filter) *xorm.Session {
	if len(filter.PType) > 0 {
		session = session.In("p_type", filter.PType)
	}
	if len(filter.V0) > 0 {
		session = session.In("v0", filter.V0)
	}
	if len(filter.V1) > 0 {
		session = session.In("v1", filter.V1)
	}
	if len(filter.V2) > 0 {
		session = session.In("v2", filter.V2)
	}
	if len(filter.V3) > 0 {
		session = session.In("v3", filter.V3)
	}
	if len(filter.V4) > 0 {
		session = session.In("v4", filter.V4)
	}
	if len(filter.V5) > 0 {
		session = session.In("v5", filter.V5)
	}
	return session
}

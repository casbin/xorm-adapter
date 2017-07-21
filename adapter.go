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

	"github.com/casbin/casbin/model"
	"github.com/casbin/casbin/util"
	"github.com/go-xorm/xorm"
	"github.com/lib/pq"
)

type Line struct {
	Data string `xorm:"varchar(100)"`
}

// Adapter represents the MySQL adapter for policy storage.
type Adapter struct {
	driverName     string
	dataSourceName string
	engine         *xorm.Engine
}

// finalizer is the destructor for Adapter.
func finalizer(a *Adapter) {
	a.engine.Close()
}

// NewAdapter is the constructor for Adapter.
func NewAdapter(driverName string, dataSourceName string) *Adapter {
	a := &Adapter{}
	a.driverName = driverName
	a.dataSourceName = dataSourceName

	// Open the DB, create it if not existed.
	a.open()

	// Call the destructor when the object is released.
	runtime.SetFinalizer(a, finalizer)

	return a
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
	defer engine.Close()

	if a.driverName == "postgres" {
		if _, err = engine.Exec("CREATE DATABASE casbin"); err != nil {
			// 42P04 is	duplicate_database
			if err.(*pq.Error).Code == "42P04" {
				return nil
			}
		}
	} else {
		_, err = engine.Exec("CREATE DATABASE IF NOT EXISTS casbin")
	}
	return err
}

func (a *Adapter) open() {
	var err error
	if err = a.createDatabase(); err != nil {
		panic(err)
	}

	var engine *xorm.Engine
	if a.driverName == "postgres" {
		engine, err = xorm.NewEngine(a.driverName, a.dataSourceName+" dbname=casbin")
	} else {
		engine, err = xorm.NewEngine(a.driverName, a.dataSourceName+"casbin")
	}
	if err != nil {
		panic(err)
	}

	a.engine = engine

	a.createTable()
}

func (a *Adapter) close() {
	a.engine.Close()
	a.engine = nil
}

func (a *Adapter) createTable() {
	err := a.engine.Sync2(new(Line))
	if err != nil {
		panic(err)
	}
}

func (a *Adapter) dropTable() {
	err := a.engine.DropTables(new(Line))
	if err != nil {
		panic(err)
	}
}

func loadPolicyLine(line string, model model.Model) {
	if line == "" {
		return
	}

	tokens := strings.Split(line, ", ")

	key := tokens[0]
	sec := key[:1]
	model[sec][key].Policy = append(model[sec][key].Policy, tokens[1:])
}

// LoadPolicy loads policy from database.
func (a *Adapter) LoadPolicy(model model.Model) error {
	var lines []Line
	err := a.engine.Table("line").Find(&lines)
	if err != nil {
		return err
	}

	for _, line := range lines {
		loadPolicyLine(line.Data, model)
	}

	return nil
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	a.dropTable()
	a.createTable()

	var lines []Line

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			tmp := ptype + ", " + util.ArrayToString(rule)
			lines = append(lines, Line{Data: tmp})
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			tmp := ptype + ", " + util.ArrayToString(rule)
			lines = append(lines, Line{Data: tmp})
		}
	}

	_, err := a.engine.Insert(&lines)
	return err
}

func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	tmp := ptype + ", " + util.ArrayToString(rule)
	line := Line{Data: tmp}

	_, err := a.engine.Insert(line)
	return err
}

func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	tmp := ptype + ", " + util.ArrayToString(rule)
	line := Line{Data: tmp}

	_, err := a.engine.Delete(line)
	return err
}

func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return errors.New("not implemented")
}

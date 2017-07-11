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
	"strings"

	"github.com/casbin/casbin/model"
	"github.com/casbin/casbin/util"
	"github.com/go-xorm/xorm"
)

type Rule struct {
	Line string `xorm:"varchar(100)"`
}


// Adapter represents the MySQL adapter for policy storage.
type Adapter struct {
	driverName     string
	dataSourceName string
	engine         *xorm.Engine
}

// NewAdapter is the constructor for Adapter.
func NewAdapter(driverName string, dataSourceName string) *Adapter {
	a := Adapter{}
	a.driverName = driverName
	a.dataSourceName = dataSourceName
	return &a
}

func (a *Adapter) createDatabase() error {
	engine, err := xorm.NewEngine(a.driverName, a.dataSourceName)
	if err != nil {
		return err
	}
	defer engine.Close()

	_, err = engine.Exec("CREATE DATABASE IF NOT EXISTS casbin")
	return err
}

func (a *Adapter) open() {
	if err := a.createDatabase(); err != nil {
		panic(err)
	}

	engine, err := xorm.NewEngine(a.driverName, a.dataSourceName+"casbin")
	if err != nil {
		panic(err)
	}

	a.engine = engine

	a.createTable()
}

func (a *Adapter) close() {
	a.engine.Close()
}

func (a *Adapter) createTable() {
	err := a.engine.Sync2(new(Rule))
	if err != nil {
		panic(err)
	}
}

func (a *Adapter) dropTable() {
	err := a.engine.DropTables(new(Rule))
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
	a.open()
	defer a.close()

	var rules []Rule
	err := a.engine.Table("rule").Find(&rules)
	if err != nil {
		return err
	}

	for _, rule := range rules {
		loadPolicyLine(rule.Line, model)
	}

	return nil
}

// SavePolicy saves policy to database.
func (a *Adapter) SavePolicy(model model.Model) error {
	a.open()
	defer a.close()

	a.dropTable()
	a.createTable()

	var rules []Rule

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			tmp := ptype + ", " + util.ArrayToString(rule)
			rules = append(rules, Rule{Line:tmp})
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			tmp := ptype + ", " + util.ArrayToString(rule)
			rules = append(rules, Rule{Line:tmp})
		}
	}

	_, err := a.engine.Insert(&rules)
	return err
}

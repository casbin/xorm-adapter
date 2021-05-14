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
	"log"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

func testGetPolicy(t *testing.T, e *casbin.Enforcer, res [][]string) {
	t.Helper()
	myRes := e.GetPolicy()
	log.Print("Policy: ", myRes)

	m := make(map[string]bool, len(res))
	for _, value := range res {
		key := strings.Join(value, ",")
		m[key] = true
	}

	for _, value := range myRes {
		key := strings.Join(value, ",")
		if !m[key] {
			t.Error("Policy: ", myRes, ", supposed to be ", res)
			break
		}
	}
}

func initPolicy(t *testing.T, driverName string, dataSourceName string, dbSpecified ...bool) {
	// Because the DB is empty at first,
	// so we need to load the policy from the file adapter (.CSV) first.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")

	a, err := NewAdapter(driverName, dataSourceName, dbSpecified...)
	if err != nil {
		panic(err)
	}

	// This is a trick to save the current policy to the DB.
	// We can't call e.SavePolicy() because the adapter in the enforcer is still the file adapter.
	// The current policy means the policy in the Casbin enforcer (aka in memory).
	err = a.SavePolicy(e.GetModel())
	if err != nil {
		panic(err)
	}

	// Clear the current policy.
	e.ClearPolicy()
	testGetPolicy(t, e, [][]string{})

	// Load the policy from DB.
	err = a.LoadPolicy(e.GetModel())
	if err != nil {
		panic(err)
	}
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testSaveLoad(t *testing.T, driverName string, dataSourceName string, dbSpecified ...bool) {
	// Initialize some policy in DB.
	initPolicy(t, driverName, dataSourceName, dbSpecified...)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	a, _ := NewAdapter(driverName, dataSourceName, dbSpecified...)
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testAutoSave(t *testing.T, driverName string, dataSourceName string, dbSpecified ...bool) {
	// Initialize some policy in DB.
	initPolicy(t, driverName, dataSourceName, dbSpecified...)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	a, _ := NewAdapter(driverName, dataSourceName, dbSpecified...)
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)

	// AutoSave is enabled by default.
	// Now we disable it.
	e.EnableAutoSave(false)

	var err error
	logErr := func(action string) {
		if err != nil {
			t.Fatalf("test action[%s] failed, err: %v", action, err)
		}
	}

	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	_, err = e.AddPolicy("alice", "data1", "write")
	logErr("AddPolicy")
	// Reload the policy from the storage to see the effect.
	err = e.LoadPolicy()
	logErr("LoadPolicy")
	// This is still the original policy.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Now we enable the AutoSave.
	e.EnableAutoSave(true)

	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	_, err = e.AddPolicy("alice", "data1", "write")
	logErr("AddPolicy2")
	// Reload the policy from the storage to see the effect.
	err = e.LoadPolicy()
	logErr("LoadPolicy2")
	// The policy has a new rule: {"alice", "data1", "write"}.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"}})

	// Remove the added rule.
	_, err = e.RemovePolicy("alice", "data1", "write")
	logErr("RemovePolicy")
	err = e.LoadPolicy()
	logErr("LoadPolicy3")
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Remove "data2_admin" related policy rules via a filter.
	// Two rules: {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"} are deleted.
	_, err = e.RemoveFilteredPolicy(0, "data2_admin")
	logErr("RemoveFilteredPolicy")
	err = e.LoadPolicy()
	logErr("LoadPolicy4")

	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
}

func testFilteredPolicy(t *testing.T, driverName string, dataSourceName string, dbSpecified ...bool) {
	// Initialize some policy in DB.
	initPolicy(t, driverName, dataSourceName, dbSpecified...)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	a, _ := NewAdapter(driverName, dataSourceName, dbSpecified...)
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf")
	// Now set the adapter
	e.SetAdapter(a)

	var err error
	logErr := func(action string) {
		if err != nil {
			t.Fatalf("test action[%s] failed, err: %v", action, err)
		}
	}

	// Load only alice's policies
	err = e.LoadFilteredPolicy(Filter{V0: []string{"alice"}})
	logErr("LoadFilteredPolicy")
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}})

	// Load only bob's policies
	err = e.LoadFilteredPolicy(Filter{V0: []string{"bob"}})
	logErr("LoadFilteredPolicy2")
	testGetPolicy(t, e, [][]string{{"bob", "data2", "write"}})

	// Load policies for data2_admin
	err = e.LoadFilteredPolicy(Filter{V0: []string{"data2_admin"}})
	logErr("LoadFilteredPolicy3")
	testGetPolicy(t, e, [][]string{{"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Load policies for alice and bob
	err = e.LoadFilteredPolicy(Filter{V0: []string{"alice", "bob"}})
	logErr("LoadFilteredPolicy4")
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
}

func testRemovePolicies(t *testing.T, driverName string, dataSourceName string, dbSpecified ...bool) {
	// Initialize some policy in DB.
	initPolicy(t, driverName, dataSourceName, dbSpecified...)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	a, _ := NewAdapter(driverName, dataSourceName, dbSpecified...)
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf")

	// Now set the adapter
	e.SetAdapter(a)

	var err error
	logErr := func(action string) {
		if err != nil {
			t.Fatalf("test action[%s] failed, err: %v", action, err)
		}
	}

	err = a.AddPolicies("p", "p", [][]string{{"max", "data2", "read"}, {"max", "data1", "write"}, {"max", "data1", "delete"}})
	logErr("AddPolicies")

	// Load policies for max
	err = e.LoadFilteredPolicy(Filter{V0: []string{"max"}})
	logErr("LoadFilteredPolicy")

	testGetPolicy(t, e, [][]string{{"max", "data2", "read"}, {"max", "data1", "write"}, {"max", "data1", "delete"}})

	// Remove policies
	err = a.RemovePolicies("p", "p", [][]string{{"max", "data2", "read"}, {"max", "data1", "write"}})
	logErr("RemovePolicies")

	// Reload policies for max
	err = e.LoadFilteredPolicy(Filter{V0: []string{"max"}})
	logErr("LoadFilteredPolicy2")

	testGetPolicy(t, e, [][]string{{"max", "data1", "delete"}})
}

func testAddPolicies(t *testing.T, driverName string, dataSourceName string, dbSpecified ...bool) {
	// Initialize some policy in DB.
	initPolicy(t, driverName, dataSourceName, dbSpecified...)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	a, _ := NewAdapter(driverName, dataSourceName, dbSpecified...)
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf")

	// Now set the adapter
	e.SetAdapter(a)

	var err error
	logErr := func(action string) {
		if err != nil {
			t.Fatalf("test action[%s] failed, err: %v", action, err)
		}
	}

	err = a.AddPolicies("p", "p", [][]string{{"max", "data2", "read"}, {"max", "data1", "write"}})
	logErr("AddPolicies")

	// Load policies for max
	err = e.LoadFilteredPolicy(Filter{V0: []string{"max"}})
	logErr("LoadFilteredPolicy")

	testGetPolicy(t, e, [][]string{{"max", "data2", "read"}, {"max", "data1", "write"}})
}

func testUpdatePolicies(t *testing.T, driverName string, dataSourceName string, dbSpecified ...bool) {
	// Initialize some policy in DB.
	initPolicy(t, driverName, dataSourceName, dbSpecified...)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	a, _ := NewAdapter(driverName, dataSourceName, dbSpecified...)
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf")

	// Now set the adapter
	e.SetAdapter(a)

	var err error
	logErr := func(action string) {
		if err != nil {
			t.Fatalf("test action[%s] failed, err: %v", action, err)
		}
	}

	err = a.UpdatePolicy("p", "p", []string{"bob", "data2", "write"}, []string{"alice", "data2", "write"})
	logErr("UpdatePolicy")

	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"alice", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	err = a.UpdatePolicies("p", "p", [][]string{{"alice", "data1", "read"}, {"alice", "data2", "write"}}, [][]string{{"bob", "data1", "read"}, {"bob", "data2", "write"}})
	logErr("UpdatePolicies")

	testGetPolicy(t, e, [][]string{{"bob", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func TestAdapters(t *testing.T) {
	// You can also use the following way to use an existing DB "abc":
	// testSaveLoad(t, "mysql", "root:@tcp(127.0.0.1:3306)/abc", true)

	testSaveLoad(t, "mysql", "root:@tcp(127.0.0.1:3306)/")
	testSaveLoad(t, "postgres", "user=postgres password=postgres host=127.0.0.1 port=5432 sslmode=disable")

	testAutoSave(t, "mysql", "root:@tcp(127.0.0.1:3306)/")
	testAutoSave(t, "postgres", "user=postgres password=postgres host=127.0.0.1 port=5432 sslmode=disable")

	testFilteredPolicy(t, "mysql", "root:@tcp(127.0.0.1:3306)/")

	testAddPolicies(t, "mysql", "root:@tcp(127.0.0.1:3306)/")
	testAddPolicies(t, "postgres", "user=postgres password=postgres host=127.0.0.1 port=5432 sslmode=disable")

	testRemovePolicies(t, "mysql", "root:@tcp(127.0.0.1:3306)/")
	testRemovePolicies(t, "postgres", "user=postgres password=postgres host=127.0.0.1 port=5432 sslmode=disable")

	testUpdatePolicies(t, "mysql", "root:@tcp(127.0.0.1:3306)/")
	testUpdatePolicies(t, "postgres", "user=postgres password=postgres host=127.0.0.1 port=5432 sslmode=disable")
}

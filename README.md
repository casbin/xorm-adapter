Xorm Adapter [![Godoc](https://godoc.org/github.com/casbin/xorm-adapter?status.svg)](https://godoc.org/github.com/casbin/xorm-adapter)
====

Xorm Adapter is the [Xorm](https://github.com/go-xorm/xorm) adapter for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load policy from Xorm supported database or save policy to it.

## Installation

    go get github.com/casbin/xorm-adapter

## Simple Example

```go
package main

import (
	"github.com/casbin/casbin"
	"github.com/casbin/xorm-adapter"
	_ "github.com/go-sql-driver/mysql"
)

func main() {
	// Initialize a Xorm adapter and use it in a Casbin enforcer:
	// The adapter will use the MySQL database named casbin.
	// If it doesn't exist, the adapter will create it automatically.
	a := xormadapter.NewAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/") // Your driver and data source. 
	e := casbin.NewEnforcer("examples/rbac_model.conf", a)
	
	// Load the policy from DB.
	e.LoadPolicy()
	
	// Check the permission.
	e.Enforce("alice", "data1", "read")
	
	// Modify the policy.
	// e.AddPolicy(...)
	// e.RemovePolicy(...)
	
	// Save the policy back to DB.
	e.SavePolicy()
}
```

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.

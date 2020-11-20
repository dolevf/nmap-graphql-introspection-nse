description = [[
Identifies webservers running GraphQL endpoints and attempts an execution of an Introspection query for information gathering.

This script queries for common graphql endpoints and then sends an Introspection query and inspects the result.

Resources
* https://graphql.org/learn/introspection/

]]


---
-- @usage 
-- nmap --script graphql-introspection.nse <target>
-- nmap -sV --script graphql-introspection <target>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 443/tcp open  ssl/http nginx
-- | graphql:
-- |_  /graphql - is vulnerable to introspection queries!
-- |_http-server-header: Jetty(9.4.z-SNAPSHOT)
---

author = "Dolev Farhi"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "fuzzer", "vuln", "intrusive"}

local http = require "http"
local vulns = require 'vulns'
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local json = require "json"

portrule = shortport.port_or_service( {80, 443}, {"http", "https"}, "tcp", "open")

-- Checks if graphql is responding to an Introspection POST request
-- @param host Hostname
-- @param port Port number
-- @return True if response is 200 and contains __schema in body
local function check_introspection(host, port)  
  local payload = { 
    query = 'query IntrospectionQuery{__schema {queryType { name }}}'
  }
  
  local gql_endpoints = {
    "/",
    "/graphql",
    "/graphiql",
    "/v1/graphql",
    "/v2/graphql",
    "/v3/graphql",
    "/playground",
    "/query"
}
  
for _, path in ipairs(gql_endpoints) do
    stdnse.debug2("Checking GraphQL at Path: %s", path)

    req = http.post(host, port, path ,{header = {["Content-Type"] = "application/json"}} , nil, (json.generate(payload)))
    
    if req.status and req.status == 200 and string.find(req.body, "__schema") then
        return "Endpoint: " .. path .. " is vulnerable to introspection queries!"
    else
        stdnse.debug2("Failed finding GraphQL at Path: %s", path)
    end

   end

   return false
end

---
--main
---
action = function(host, port)
  local vuln = {
    state = vulns.STATE.NOT_VULN,
    description = [[
Checks if GraphQL allows Introspection Queries.
    ]],
    references = {
        'https://graphql.org/learn/introspection/'
    }
  }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  stdnse.debug1("GraphQL Instrospection check is running...")
  result = check_introspection(host, port)
  
  if result then
    stdnse.debug1("GraphQL Introspection is enabled.")
    vuln.title = 'GraphQL Server allows Introspection queries at endpoint: ' .. result
    vuln.state = vulns.STATE.VULN
  end

  return vuln_report:make_output(vuln)

end

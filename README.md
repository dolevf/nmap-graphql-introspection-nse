# Nmap NSE for GraphQL
Intifies webservers running GraphQL endpoints and attempts an execution of an Introspection query for information gathering.

# Usage
Move the file into nmap's `scripts` folder:
`cp -i graphql-introspection.nse /usr/share/nmap/scripts`

Execute a scan:
`nmap -sV --script=graphql-introspection -v ip.add.re.ss`

# Resources
* https://graphql.org/learn/introspection/

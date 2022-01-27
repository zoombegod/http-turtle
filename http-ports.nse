local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Find HTTP services by sending an HTTP request to all open ports.
]]

--@output
-- PORT   STATE    SERVICE
-- 80/tcp open     http
-- | http-ports:
-- |_  http_port: 93.184.216.34:80

author = "Timon Vogel"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


portrule = shortport.http

action = function(host, port)

  local output = stdnse.output_table()
  local r = http.get( host, port, "" )

  if r then
    output.http_port = host.ip .. ":" .. port.number
  end
  return output
end

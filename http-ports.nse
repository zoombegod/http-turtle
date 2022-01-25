local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Find HTTP services by sending an HTTP request to all open ports.
]]

--@output
-- Nmap scan report for scanme.nmap.org (74.207.244.221)
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-title: Go ahead and ScanMe!
-- Nmap scan report for scanme.nmap.org (45.33.32.156)
-- PORT     STATE    SERVICE
-- 80/tcp   open     http
-- | gehttp: 
-- |   status: 200
-- |   version: 1.1
-- |   header: 
-- |     vary: Accept-Encoding
-- |     server: Apache/2.4.7 (Ubuntu)
-- |     accept-ranges: bytes
-- |     content-type: text/html
-- |     transfer-encoding: chunked
-- |     connection: close
-- |     date: Tue, 25 Jan 2022 11:52:11 GMT
-- |   rawheader: 
-- |     Date: Tue, 25 Jan 2022 11:52:11 GMT
-- |     Server: Apache/2.4.7 (Ubuntu)
-- |     Accept-Ranges: bytes
-- |     Vary: Accept-Encoding
-- |     Connection: close
-- |     Transfer-Encoding: chunked
-- |     Content-Type: text/html
-- |_    

author = "Timon Vogel"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}


portrule = shortport.http

action = function(host, port)

  local output = stdnse.output_table()

  local r = http.get( host, port, "" )

  if r then
    output.http_port = port.number
  end

  return output
end

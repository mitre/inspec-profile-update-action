control 'SV-221519' do
  title 'OHS must be tuned to handle the operational requirements of the hosted application.'
  desc 'A Denial of Service (DoS) can occur when the web server is so overwhelmed that it can no longer respond to additional requests. A web server not properly tuned may become overwhelmed and cause a DoS condition even with expected traffic from users. To avoid a DoS, the web server must be tuned to handle the expected traffic for the hosted applications.'
  desc 'check', '1. Check to see if the following directives have been set appropriately for the server and application:
MaxClients
MPM Module
-worker (StartServers, MinSpareThreads, MaxSpareThreads, ThreadsPerChild)
Timeout
KeepAlive
KeepAliveTimeout
MaxKeepAliveRequests
ListenBacklog
LimitRequestBody
LimitRequestFields
LimitRequestFieldSize
LimitRequestLine
LimitXMLRequestBody
LimitInternalRecursion

2. If the above directives have not been set to address the specific needs of the web server and applications, this is a finding.'
  desc 'fix', 'Set the following directives appropriately for the server and application:
MaxClients
MPM Module
-worker (StartServers, MinSpareThreads, MaxSpareThreads, ThreadsPerChild)
Timeout
KeepAlive
KeepAliveTimeout
MaxKeepAliveRequests
ListenBacklog
LimitRequestBody
LimitRequestFields
LimitRequestFieldSize
LimitRequestLine
LimitXMLRequestBody
LimitInternalRecursion'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23234r415236_chk'
  tag severity: 'medium'
  tag gid: 'V-221519'
  tag rid: 'SV-221519r415238_rule'
  tag stig_id: 'OH12-1X-000307'
  tag gtitle: 'SRG-APP-000435-WSR-000148'
  tag fix_id: 'F-23223r415237_fix'
  tag 'documentable'
  tag legacy: ['SV-79019', 'V-64529']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end

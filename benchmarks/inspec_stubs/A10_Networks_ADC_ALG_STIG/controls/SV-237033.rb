control 'SV-237033' do
  title 'The A10 Networks ADC, when used to load balance web applications, must enable external logging for accessing Web Application Firewall data event messages.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

External logging must be enabled for WAF data event messages. Create a server configuration for each log server, and then add a TCP or UDP port to each server configuration, with the port number on which the external log server listens for log messages.'
  desc 'check', 'If the device is not used to load balance web servers, this is not applicable.

Review the device configuration and ask the device Administrator which templates are used. 

If no SLB instance for the log server(s) is configured, this is a finding.

If there is no service group with assigned members for the log servers or the service group is not included in the logging template, this is a finding.

If no logging template is configured and bound to the WAF template, this is a finding.'
  desc 'fix', 'If the device is used to load balance web servers, configure external logging for WAF data event messages. 

Create a server configuration for each log server. 
The following command adds a server:
slb server [server-name] [ipaddr]

The following command specifies the TCP or UDP port number on which the server will listen for log traffic:
port [port-num] [tcp | udp]

If multiple log servers are used, add the log servers to a service group. Use the round-robin load-balancing method, which is the default method.

The following command creates the service group:
slb service-group [group-name] [tcp | udp]

The following command adds each log server and its TCP or UDP port to the service group:
member [server-name:portnum]

The following command creates a logging template:
slb template logging [template-name]

The following command adds the service group containing the log servers to the logging template:
service-group [group-name]

The following commands bind the logging template to the WAF template:
slb template waf [template-name]
template logging [template-name]'
  impact 0.3
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40252r639544_chk'
  tag severity: 'low'
  tag gid: 'V-237033'
  tag rid: 'SV-237033r639546_rule'
  tag stig_id: 'AADC-AG-000023'
  tag gtitle: 'SRG-NET-000077-ALG-000046'
  tag fix_id: 'F-40215r639545_fix'
  tag 'documentable'
  tag legacy: ['SV-82449', 'V-67959']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end

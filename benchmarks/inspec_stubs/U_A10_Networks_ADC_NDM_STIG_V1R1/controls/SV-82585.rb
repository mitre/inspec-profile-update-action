control 'SV-82585' do
  title 'The A10 Networks ADC must only allow the use of secure protocols that implement cryptographic mechanisms to protect the integrity of maintenance and diagnostic communications for nonlocal maintenance sessions.'
  desc 'This requires the use of secure protocols instead of their unsecured counterparts, such as SSH instead of telnet, SCP instead of FTP, and HTTPS instead of HTTP. If unsecured protocols (lacking cryptographic mechanisms) are used for sessions, the contents of those sessions will be susceptible to manipulation, potentially allowing alteration and hijacking of maintenance sessions.'
  desc 'check', 'Review the device configuration.

The following command shows the types of management access allowed on each of the interfaces:
show management [ipv4 | ipv6]

The following command shows IPv4 management access information:
show management ipv4

If either Telnet or HTTP is listed as "on" for any interface, this is a finding.

The following command shows IPv6 management access information:
show management ipv6

If either Telnet or HTTP is listed as "on" for any interface, this is a finding.

Verify that HTTP for management is disabled.
show web-service

If HTTP is enabled, this is a finding.

HTTPS is allowed for management and is enabled by default.'
  desc 'fix', 'The following commands enable management access to the device and the use of SSH, HTTPS, Syslog, and SNMP:
enable-management
service ssh https syslog snmp snmp-trap

Disable HTTP on the management interface:
no enable-management service http management
Note: Do not configure any management protocols on any of the other interfaces.

Disable the web server (HTTP for management):
no web-service server'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68655r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68095'
  tag rid: 'SV-82585r1_rule'
  tag stig_id: 'AADC-NM-000144'
  tag gtitle: 'SRG-APP-000411-NDM-000330'
  tag fix_id: 'F-74209r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end

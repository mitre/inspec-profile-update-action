control 'SV-82545' do
  title 'The A10 Networks ADC must prohibit the use of unencrypted protocols for network access to privileged accounts.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Network devices can accomplish this by making direct function calls to encryption modules or by leveraging operating system encryption capabilities.'
  desc 'check', 'Review the device configuration.

The following command show the types of management access allowed on each of the interfaces:
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
  desc 'fix', 'Configure the device to prohibit the use of Telnet and HTTP for device management.

The following commands enable management access to the device and the use of SSH, HTTPS, Syslog, and SNMP:
enable-management
service ssh https syslog snmp snmp-trap

Disable HTTP on the management interface:
no enable-management service http management

Note: Do not configure any management protocols on any of the other interfaces.

Disable the web server (HTTP for management).
no web-service server'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68615r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68055'
  tag rid: 'SV-82545r1_rule'
  tag stig_id: 'AADC-NM-000062'
  tag gtitle: 'SRG-APP-000172-NDM-000259'
  tag fix_id: 'F-74171r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end

control 'SV-237034' do
  title 'The A10 Networks ADC must send an alert to, at a minimum, the ISSO and SCA when connectivity to the Syslog servers is lost.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Possible audit processing failures also include the inability of device to write to the central audit log.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations, (i.e., all audit data storage repositories combined), or both.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Review the device configuration.

The following command shows the configured Server Load Balancing instances:
show run | sec slb

If no Server Load Balancing instance is configured with a health check to the Syslog server, this is a finding.

The following command shows the device configuration and filters the output on the string "snmp":
show run | inc snmp

This will include which SNMP traps the device is configured to send.

If the output does not include "snmp-server enable traps slb server-down", this is a finding.'
  desc 'fix', 'The following command enables the device to send an SNMP trap when the health monitor shows the connection to the server is down:
snmp-server enable traps slb server-down

The following command enables the device to send an SNMP trap when the health monitor shows the connection to the server is up:
snmp enable traps slb server-up

The following command creates a health monitor for UDP 514 (the Syslog port):
health monitor [monitor name]
method udp port 514

The following command creates a Server Load Balancing instance and assigns a health monitor to it:
slb server server-name [ipaddr | hostname]
health-check [monitor]'
  impact 0.3
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40253r639547_chk'
  tag severity: 'low'
  tag gid: 'V-237034'
  tag rid: 'SV-237034r639549_rule'
  tag stig_id: 'AADC-AG-000026'
  tag gtitle: 'SRG-NET-000088-ALG-000054'
  tag fix_id: 'F-40216r639548_fix'
  tag 'documentable'
  tag legacy: ['SV-82451', 'V-67961']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end

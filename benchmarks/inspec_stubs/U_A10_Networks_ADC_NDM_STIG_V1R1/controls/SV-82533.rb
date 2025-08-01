control 'SV-82533' do
  title 'The A10 Networks ADC must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

Since the A10 Networks ADC can monitor connectivity to servers, it can be configured to perform a health check of the Syslog servers. When connectivity is lost or the health check fails for another reason, it can send an SNMP trap notifying authorized personnel.'
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

The following command enables the device to send an SNMP trap when the health-monitor shows the connection to the server is up:
snmp enable traps slb server-up

The following command creates a health monitor for UDP 514 (the Syslog port):
health monitor [monitor name]
method udp port 514

The following command creates a Server Load Balancing instance and assigns a health monitor to it:
slb server server-name [ipaddr | hostname]
health-check [monitor]'
  impact 0.3
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68603r1_chk'
  tag severity: 'low'
  tag gid: 'V-68043'
  tag rid: 'SV-82533r1_rule'
  tag stig_id: 'AADC-NM-000033'
  tag gtitle: 'SRG-APP-000108-NDM-000232'
  tag fix_id: 'F-74159r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end

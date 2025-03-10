control 'SV-216547' do
  title 'The Cisco router must be configured to send log data to a syslog server for the purpose of forwarding alerts to the administrators and the ISSO.'
  desc 'The aggregation of log data kept on a syslog server can be used to detect attacks and trigger an alert to the appropriate security personnel. The stored log data can used to detect weaknesses in security that enable the network IA team to find and address these weaknesses before breaches can occur. Reviewing these logs, whether before or after a security breach, are important in showing whether someone is an internal employee or an outside threat.'
  desc 'check', 'Verify that the router is configured to send logs to a syslog server. The configuration should look similar to the example below:

logging 10.1.3.22 vrf default severity info

If the router is not configured to send log data to the syslog server, this is a finding.'
  desc 'fix', 'Configure the router to send log messages to the syslog server as shown in the example below.

RP/0/0/CPU0:R3(config)#logging 10.1.3.22 severity info'
  impact 0.7
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17782r288327_chk'
  tag severity: 'high'
  tag gid: 'V-216547'
  tag rid: 'SV-216547r531088_rule'
  tag stig_id: 'CISC-ND-001450'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-17779r288328_fix'
  tag 'documentable'
  tag legacy: ['SV-105635', 'V-96497']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

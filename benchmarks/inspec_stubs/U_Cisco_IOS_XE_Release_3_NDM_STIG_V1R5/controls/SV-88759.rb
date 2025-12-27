control 'SV-88759' do
  title 'The Cisco IOS XE router must be configured to send log data to a syslog server for the purpose of forwarding alerts to the administrators and the ISSO.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply create a new account. Notification of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of accounts and notifies administrators and Information System Security Officers (ISSOs). Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.'
  desc 'check', 'Verify that the Cisco IOS XE router is configured to send logs to a syslog server.

The configuration should look similar to the example below:

Logging trap information
logging host x.x.x.x

If the router is not configured to send log data to the syslog server, this is a finding.'
  desc 'fix', 'Add the following commands to the router configuration to send log data to the syslog server:

logging trap information
logging host x.x.x.x'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74177r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74085'
  tag rid: 'SV-88759r2_rule'
  tag stig_id: 'CISR-ND-000142'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-80625r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

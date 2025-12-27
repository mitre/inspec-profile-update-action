control 'SV-215708' do
  title 'The Cisco router must be configured to off-load log records onto a different system than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement as shown in the example below.

logging trap notifications
logging x.x.x.x

Note: Default for sending log messages to the syslog server is informational (level 6); hence, the command logging trap informational will not be seen in the configuration. Level of log messages sent to the syslog server can be verified using the show logging command.

If the Cisco router is not configured to off-load log records onto a different system than the system being audited, this is a finding.'
  desc 'fix', 'Configure the Cisco router to send log records to a syslog server as shown in the example below.

R4(config)#logging host x.x.x.x
R4(config)#logging trap notifications'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-16902r286086_chk'
  tag severity: 'medium'
  tag gid: 'V-215708'
  tag rid: 'SV-215708r521266_rule'
  tag stig_id: 'CISC-ND-001310'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-16900r286087_fix'
  tag 'documentable'
  tag legacy: ['SV-105301', 'V-96163']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

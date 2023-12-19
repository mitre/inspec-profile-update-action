control 'SV-220616' do
  title 'The Cisco switch must be configured to off-load log records onto a different system than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Review the Cisco switch configuration to verify that it off-loads log records onto a different system than the system being audited as shown in the example below:

logging trap notifications
logging x.x.x.x

Note: The default for sending log messages to the syslog server is informational (level 6); hence, the command logging trap information will not be seen in the configuration. The level of log messages sent to the syslog server can be verified using the show logging command.

If the Cisco switch is not configured to off-load log records onto a different system than the system being audited, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to send log records to a syslog server as shown in the example below:

SW4(config)#logging host x.x.x.x
SW4(config)#logging trap notifications'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22331r507894_chk'
  tag severity: 'medium'
  tag gid: 'V-220616'
  tag rid: 'SV-220616r521267_rule'
  tag stig_id: 'CISC-ND-001310'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-22320r507895_fix'
  tag 'documentable'
  tag legacy: ['SV-110461', 'V-101357']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

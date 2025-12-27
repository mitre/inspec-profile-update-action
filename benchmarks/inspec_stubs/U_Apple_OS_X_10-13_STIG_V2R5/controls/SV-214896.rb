control 'SV-214896' do
  title 'The macOS firewall must have logging enabled.'
  desc 'Firewall logging must be enabled. This ensures that malicious network activity will be logged to the system.'
  desc 'check', 'If HBSS is used, this is not applicable.

To check if the macOS firewall has logging enabled, run the following command:

/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode | /usr/bin/grep on

If the result does not show "on", this is a finding.'
  desc 'fix', 'To enable the firewall logging, run the following command:

/usr/bin/sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16096r397260_chk'
  tag severity: 'medium'
  tag gid: 'V-214896'
  tag rid: 'SV-214896r609363_rule'
  tag stig_id: 'AOSX-13-000950'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16094r397261_fix'
  tag 'documentable'
  tag legacy: ['V-81671', 'SV-96385']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-90797' do
  title 'The OS X firewall must have logging enabled.'
  desc 'Firewall logging must be enabled. This ensures that malicious network activity will be logged to the system.'
  desc 'check', 'If HBSS is used, this is not applicable.

To check if the OS X firewall has logging enabled, run the following command:

/usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode | /usr/bin/grep on

If the result does not show "on", this is a finding.'
  desc 'fix', 'To enable the firewall logging, run the following command:

/usr/bin/sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75793r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76109'
  tag rid: 'SV-90797r1_rule'
  tag stig_id: 'AOSX-12-000950'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82747r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

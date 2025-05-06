control 'SV-214901' do
  title 'The macOS Application Firewall must be enabled.'
  desc 'The Application Firewall is the built-in firewall that comes with macOS and must be enabled. Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.'
  desc 'check', 'If an approved HBSS solution is installed, this is not applicable.

To check if the macOS firewall has been enabled, run the following command:

/usr/bin/sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

If the result is "disabled", this is a finding.'
  desc 'fix', 'To enable the firewall, run the following command:

/usr/bin/sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16101r397275_chk'
  tag severity: 'medium'
  tag gid: 'V-214901'
  tag rid: 'SV-214901r609363_rule'
  tag stig_id: 'AOSX-13-001080'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag fix_id: 'F-16099r397276_fix'
  tag 'documentable'
  tag legacy: ['SV-96395', 'V-81681']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

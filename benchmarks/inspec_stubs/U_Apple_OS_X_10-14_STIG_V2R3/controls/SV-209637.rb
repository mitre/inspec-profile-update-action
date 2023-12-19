control 'SV-209637' do
  title 'The macOS Application Firewall must be enabled.'
  desc 'Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.'
  desc 'check', 'If an approved HBSS solution is installed, this is Not Applicable.

To check if the macOS firewall has been enabled, run the following command:

/usr/bin/sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

If the result is "disabled", this is a finding.'
  desc 'fix', 'To enable the firewall, run the following command:

/usr/bin/sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9888r282393_chk'
  tag severity: 'medium'
  tag gid: 'V-209637'
  tag rid: 'SV-209637r610285_rule'
  tag stig_id: 'AOSX-14-005050'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag fix_id: 'F-9888r282394_fix'
  tag 'documentable'
  tag legacy: ['SV-105137', 'V-95999']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

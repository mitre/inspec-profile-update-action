control 'SV-90807' do
  title 'The OS X Application Firewall must be enabled.'
  desc 'The Application Firewall is the built-in firewall that comes with OS X and must be enabled. Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.'
  desc 'check', 'If an approved HBSS solution is installed, this is not applicable.

To check if the OS X firewall has been enabled, run the following command:

/usr/bin/sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

If the result is "disabled", this is a finding.'
  desc 'fix', 'To enable the firewall, run the following command:

/usr/bin/sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75805r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76119'
  tag rid: 'SV-90807r1_rule'
  tag stig_id: 'AOSX-12-001080'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag fix_id: 'F-82757r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

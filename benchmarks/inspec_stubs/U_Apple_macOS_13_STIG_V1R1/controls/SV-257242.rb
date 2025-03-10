control 'SV-257242' do
  title 'The macOS Application Firewall must be enabled.'
  desc 'Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.'
  desc 'check', 'Verify the macOS system is configured to enable the built-in firewall with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "EnableFirewall\\|EnableStealthMode"

EnableFirewall = 1;
EnableStealthMode = 1;

If "EnableFirewall" and "EnableStealthMode" are not set to "1", this is a finding.'
  desc 'fix', 'Configure the macOS system to enable the built-in firewall by installing the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60927r905357_chk'
  tag severity: 'medium'
  tag gid: 'V-257242'
  tag rid: 'SV-257242r905359_rule'
  tag stig_id: 'APPL-13-005050'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag fix_id: 'F-60868r905358_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-252536' do
  title 'The macOS Application Firewall must be enabled.'
  desc 'Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.'
  desc 'check', %q(Verify that the built-in firewall is enabled:

# /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep 'EnableFirewall\|EnableStealthMode' 
 
If the return is not "EnableFirewall = 1;" and "EnableStealthMode = 1;" this is a finding.

If the built-in firewall is not enabled, ask the System Administrator if another application firewall is installed and enabled.  
 
If no application firewall is installed and enabled, this is a finding.)
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55992r877366_chk'
  tag severity: 'medium'
  tag gid: 'V-252536'
  tag rid: 'SV-252536r877367_rule'
  tag stig_id: 'APPL-12-005050'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag fix_id: 'F-55942r816421_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

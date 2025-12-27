control 'SV-218178' do
  title 'The /etc/sysctl.conf file must not have an extended ACL.'
  desc "The sysctl.conf file specifies the values for kernel parameters to be set on boot.  These settings can affect the system's security."
  desc 'check', "Check the permissions of the file.

# ls -lL /etc/sysctl.conf

If the permissions of the file or directory contain a '+', an extended ACL is present. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/sysctl.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19653r561470_chk'
  tag severity: 'medium'
  tag gid: 'V-218178'
  tag rid: 'SV-218178r603259_rule'
  tag stig_id: 'GEN000000-LNX00530'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19651r561471_fix'
  tag 'documentable'
  tag legacy: ['V-22596', 'SV-62983']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

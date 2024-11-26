control 'SV-26999' do
  title 'The /etc/sysctl.conf file must not have an extended ACL.'
  desc "The sysctl.conf file specifies the values for kernel parameters to be set on boot.  These settings can affect the system's security."
  desc 'check', "Check the permissions of the file.

# ls -lL /etc/sysctl.conf

If the permissions of the file or directory contain a '+', an extended ACL is present. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/sysctl.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35992r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22596'
  tag rid: 'SV-26999r1_rule'
  tag stig_id: 'GEN000000-LNX00530'
  tag gtitle: 'GEN000000-LNX00530'
  tag fix_id: 'F-24265r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

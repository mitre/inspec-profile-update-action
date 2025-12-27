control 'SV-44758' do
  title 'The /etc/sysctl.conf file must not have an extended ACL.'
  desc "The sysctl.conf file specifies the values for kernel parameters to be set on boot.  These settings can affect the system's security."
  desc 'check', "Check the permissions of the file.
# ls -lLd /etc/sysctl.conf
If the permissions of the file or directory contains a '+', an extended ACL is present. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/sysctl.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42263r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22596'
  tag rid: 'SV-44758r1_rule'
  tag stig_id: 'GEN000000-LNX00530'
  tag gtitle: 'GEN000000-LNX00530'
  tag fix_id: 'F-38208r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-44656' do
  title 'The /etc/sysctl.conf file must be group-owned by root.'
  desc "The sysctl.conf file specifies the values for kernel parameters to be set on boot.  These settings can affect the system's security."
  desc 'check', 'Check /etc/sysctl.conf group ownership: 
# ls -lL /etc/sysctl.conf 
If /etc/sysctl.conf is not group-owned by root, this is a finding.'
  desc 'fix', 'Use the chgrp command to change the group owner of /etc/sysctl.conf to root:
# chgrp root /etc/sysctl.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42160r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4335'
  tag rid: 'SV-44656r1_rule'
  tag stig_id: 'GEN000000-LNX00500'
  tag gtitle: 'GEN000000-LNX00500'
  tag fix_id: 'F-38111r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

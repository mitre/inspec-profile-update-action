control 'SV-45758' do
  title 'The inetd.conf file, xinetd.conf file, and the xinetd.d directory must be group-owned by root, bin, sys, or system.'
  desc "Failure to give ownership of sensitive files or utilities to system groups may provide unauthorized users with the potential to access sensitive information or change the system configuration possibly weakening the system's security posture."
  desc 'check', 'Check the group ownership of the xinetd configuration files and directories.

Procedure:
# ls -alL /etc/xinetd.conf /etc/xinetd.d


If a file or directory is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group-owner of the xinetd configuration files and directories.

Procedure:
# chgrp -R root /etc/xinetd.conf /etc/xinetd.d'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43112r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22423'
  tag rid: 'SV-45758r1_rule'
  tag stig_id: 'GEN003730'
  tag gtitle: 'GEN003730'
  tag fix_id: 'F-39158r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

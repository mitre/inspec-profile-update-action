control 'SV-44997' do
  title 'The /etc/group file must be group-owned by root, bin, sys, or system.'
  desc 'The /etc/group file is critical to system security and must be protected from unauthorized modification.  The group file contains a list of system groups and associated information.'
  desc 'check', 'Check the group ownership of the /etc/group file.

Procedure:
# ls -lL /etc/group

If the file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group-owner of the /etc/group file.

Procedure:
# chgrp root /etc/group'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42402r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22336'
  tag rid: 'SV-44997r1_rule'
  tag stig_id: 'GEN001392'
  tag gtitle: 'GEN001392'
  tag fix_id: 'F-38412r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

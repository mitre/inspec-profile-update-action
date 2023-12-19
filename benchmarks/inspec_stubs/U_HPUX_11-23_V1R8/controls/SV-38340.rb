control 'SV-38340' do
  title 'The /etc/shadow file (or equivalent) must be group-owned by root, bin, sys or other.'
  desc 'The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', 'For Trusted Mode:
Check the TCB auth files and directories.
# ls -lLd /tcb /tcb/files /tcp/files/auth 
# ls -lL /tcb/files/auth/[a-z,A-Z]/*

If the group-owner of any of the /tcb files and directories is not root, bin, sys, or other, this is a finding.

For SMSE:
Check the /etc/shadow file.
# ls -lL /etc/shadow

If the /etc/shadow file is not group-owned by root, bin, sys or other, this is a finding.'
  desc 'fix', 'For Trusted Mode:
# chgrp root /tcb
#chgrp root /tcb/files /tcb/files/auth
# chgrp root  /tcb/files/auth/[a-z]/* 

For SMSE:
# chgrp root /etc/shadow'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36356r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22339'
  tag rid: 'SV-38340r2_rule'
  tag stig_id: 'GEN001410'
  tag gtitle: 'GEN001410'
  tag fix_id: 'F-31655r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-38727' do
  title 'The /etc/security/passwd file must be group-owned by security, bin, sys, or system.'
  desc 'The /etc/security/passwd file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', 'Check the ownership of the /etc/security/passwd file.

Procedure:
# ls -lL 
/etc/security/passwd

If the file is not group-owned by security, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/security/passwd file to security, bin, sys, or system.

Procedure:
# chgrp security /etc/security/passwd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37027r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22339'
  tag rid: 'SV-38727r1_rule'
  tag stig_id: 'GEN001410'
  tag gtitle: 'GEN001410'
  tag fix_id: 'F-32296r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

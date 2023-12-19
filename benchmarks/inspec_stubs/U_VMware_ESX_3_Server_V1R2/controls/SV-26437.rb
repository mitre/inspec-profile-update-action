control 'SV-26437' do
  title 'The /etc/shadow file (or equivalent) must be group-owned by root, bin, sys, or system.'
  desc 'The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', 'Check the ownership of the /etc/shadow file.

Procedure:
# ls -lL /etc/shadow

If the file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/shadow file.

Procedure:
# chgrp root /etc/shadow'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27511r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22339'
  tag rid: 'SV-26437r1_rule'
  tag stig_id: 'GEN001410'
  tag gtitle: 'GEN001410'
  tag fix_id: 'F-23627r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

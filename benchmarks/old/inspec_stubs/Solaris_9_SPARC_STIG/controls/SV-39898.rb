control 'SV-39898' do
  title 'The /etc/passwd file must be group-owned by root, bin, or sys.'
  desc 'The /etc/passwd file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.'
  desc 'fix', 'Change the group owner of the /etc/passwd file to root, bin, or sys.

Procedure:
# chgrp root /etc/passwd'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22333'
  tag rid: 'SV-39898r1_rule'
  tag stig_id: 'GEN001379'
  tag gtitle: 'GEN001379'
  tag fix_id: 'F-34055r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

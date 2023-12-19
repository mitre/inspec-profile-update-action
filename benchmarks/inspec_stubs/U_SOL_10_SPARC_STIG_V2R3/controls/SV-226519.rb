control 'SV-226519' do
  title 'The /etc/group file must be group-owned by root, bin, or sys.'
  desc 'The /etc/group file is critical to system security and must be protected from unauthorized modification.  The group file contains a list of system groups and associated information.'
  desc 'check', 'Check the group ownership of the /etc/group file.

Procedure:
# ls -lL /etc/group

If the file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/group file.

Procedure:
# chgrp root /etc/group'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28680r482945_chk'
  tag severity: 'medium'
  tag gid: 'V-226519'
  tag rid: 'SV-226519r603265_rule'
  tag stig_id: 'GEN001392'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28668r482946_fix'
  tag 'documentable'
  tag legacy: ['SV-39899', 'V-22336']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

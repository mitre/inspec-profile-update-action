control 'SV-218297' do
  title 'The /etc/group file must be group-owned by root, bin, or sys.'
  desc 'The /etc/group file is critical to system security and must be protected from unauthorized modification.  The group file contains a list of system groups and associated information.'
  desc 'check', 'Check the group ownership of the /etc/group file.

Procedure:
# ls -lL /etc/group

If the file is not group-owned by root, bin or sys, this is a finding.'
  desc 'fix', 'Change the group-owner of the /etc/group file.

Procedure:
# chgrp root /etc/group'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19772r561680_chk'
  tag severity: 'medium'
  tag gid: 'V-218297'
  tag rid: 'SV-218297r603259_rule'
  tag stig_id: 'GEN001392'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19770r561681_fix'
  tag 'documentable'
  tag legacy: ['V-22336', 'SV-64563']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

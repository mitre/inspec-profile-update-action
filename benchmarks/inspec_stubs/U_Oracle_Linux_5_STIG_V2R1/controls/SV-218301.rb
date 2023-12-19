control 'SV-218301' do
  title 'The /etc/shadow file (or equivalent) must be group-owned by root, bin, or sys.'
  desc 'The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', 'Check the ownership of the /etc/shadow file.

Procedure:
# ls -lL /etc/shadow

If the file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group-owner of the /etc/shadow file.

Procedure:
# chgrp root /etc/shadow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19776r561692_chk'
  tag severity: 'medium'
  tag gid: 'V-218301'
  tag rid: 'SV-218301r603259_rule'
  tag stig_id: 'GEN001410'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19774r561693_fix'
  tag 'documentable'
  tag legacy: ['V-22339', 'SV-64571']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

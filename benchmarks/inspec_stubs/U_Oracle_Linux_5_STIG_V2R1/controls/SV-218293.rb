control 'SV-218293' do
  title 'The /etc/passwd file must be group-owned by root, bin, or sys.'
  desc 'The /etc/passwd file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.'
  desc 'check', 'Check the group ownership of the passwd file.

Procedure:
# ls -lL /etc/passwd

If the file is not group-owned by root, bin or sys, this is a finding.'
  desc 'fix', 'Change the group-owner of the /etc/passwd file to root, bin or sys.

Procedure:
# chgrp root /etc/passwd'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19768r561668_chk'
  tag severity: 'medium'
  tag gid: 'V-218293'
  tag rid: 'SV-218293r603259_rule'
  tag stig_id: 'GEN001379'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19766r561669_fix'
  tag 'documentable'
  tag legacy: ['V-22333', 'SV-64553']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

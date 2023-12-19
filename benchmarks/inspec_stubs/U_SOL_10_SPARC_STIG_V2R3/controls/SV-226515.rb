control 'SV-226515' do
  title 'The /etc/passwd file must be group-owned by root, bin, or sys.'
  desc 'The /etc/passwd file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.'
  desc 'check', 'Check the group ownership of the passwd file.

Procedure:
# ls -lL /etc/passwd

If the file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/passwd file to root, bin, or sys.

Procedure:
# chgrp root /etc/passwd'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28676r482933_chk'
  tag severity: 'medium'
  tag gid: 'V-226515'
  tag rid: 'SV-226515r603265_rule'
  tag stig_id: 'GEN001379'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28664r482934_fix'
  tag 'documentable'
  tag legacy: ['SV-39898', 'V-22333']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

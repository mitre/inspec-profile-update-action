control 'SV-218184' do
  title 'The /etc/securetty file must have mode 0600 or less permissive.'
  desc 'The securetty file contains the list of terminals permitting direct root logins.  It must be protected from unauthorized modification.'
  desc 'check', 'Check /etc/securetty permissions.

Procedure:
# ls -lL /etc/securetty

If /etc/securetty has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/securetty file to 0600.

Procedure:
# chmod 0600 /etc/securetty'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19659r553889_chk'
  tag severity: 'medium'
  tag gid: 'V-218184'
  tag rid: 'SV-218184r603259_rule'
  tag stig_id: 'GEN000000-LNX00660'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19657r553890_fix'
  tag 'documentable'
  tag legacy: ['V-12040', 'SV-63071']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end

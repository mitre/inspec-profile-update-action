control 'SV-218183' do
  title 'The /etc/securetty file must be owned by root.'
  desc 'The securetty file contains the list of terminals permitting direct root logins.  It must be protected from unauthorized modification.'
  desc 'check', 'Check /etc/securetty ownership.

Procedure:
# ls -lL /etc/securetty

If /etc/securetty is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/securetty file to root.

Procedure:
# chown root /etc/securetty'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19658r553886_chk'
  tag severity: 'medium'
  tag gid: 'V-218183'
  tag rid: 'SV-218183r603259_rule'
  tag stig_id: 'GEN000000-LNX00640'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19656r553887_fix'
  tag 'documentable'
  tag legacy: ['V-12039', 'SV-63061']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end

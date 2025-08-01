control 'SV-44700' do
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
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42204r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12040'
  tag rid: 'SV-44700r1_rule'
  tag stig_id: 'GEN000000-LNX00660'
  tag gtitle: 'GEN000000-LNX00660'
  tag fix_id: 'F-38154r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end

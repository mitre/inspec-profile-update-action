control 'SV-44672' do
  title 'The /etc/securetty file must be owned by root.'
  desc 'The securetty file contains the list of terminals permitting direct root logins.  It must be protected from unauthorized modification.'
  desc 'check', 'Check /etc/securetty ownership.

Procedure:
# ls –lL /etc/securetty

If /etc/securetty is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/securetty file to root.

Procedure:
# chown root /etc/securetty'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42177r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12039'
  tag rid: 'SV-44672r1_rule'
  tag stig_id: 'GEN000000-LNX00640'
  tag gtitle: 'GEN000000-LNX00640'
  tag fix_id: 'F-38126r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end

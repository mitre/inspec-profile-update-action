control 'SV-46143' do
  title 'The /etc/news/incoming.conf (or equivalent) must have mode 0600 or less permissive.'
  desc 'Excessive permissions on the "incoming.conf" file may allow unauthorized modification which could lead to Denial-of-Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'SUSE ships the InternetNewsDaemon (innd) news server. The file corresponding to "/etc/news/hosts.nntp" is "/etc/news/incoming.conf". Check the permissions for "/etc/news/incoming.conf".

# ls -lL /etc/news/incoming.conf

If "/etc/news/incoming.conf" has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the "/etc/news/incoming.conf" file to 0600.

# chmod 0600 /etc/news/incoming/conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43404r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4273'
  tag rid: 'SV-46143r1_rule'
  tag stig_id: 'GEN006260'
  tag gtitle: 'GEN006260'
  tag fix_id: 'F-39486r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

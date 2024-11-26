control 'SV-45896' do
  title 'The /etc/news/readers.conf (or equivalent) must have mode 0600 or less permissive.'
  desc 'Excessive permissions on the readers.conf file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check the permissions for "/etc/news/readers.conf".

# ls -lL /etc/news/readers.conf

If /etc/news/readers.conf has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/news/readers.conf file to 0600.
# chmod 0600 /etc/news/readers.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43207r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4275'
  tag rid: 'SV-45896r1_rule'
  tag stig_id: 'GEN006300'
  tag gtitle: 'GEN006300'
  tag fix_id: 'F-39274r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-218656' do
  title 'The /etc/news/readers.conf (or equivalent) must have mode 0600 or less permissive.'
  desc 'Excessive permissions on the readers.conf file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'Check the permissions for "/etc/news/readers.conf".

# ls -lL /etc/news/readers.conf

If /etc/news/readers.conf has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/news/readers.conf file to 0600.
# chmod 0600 /etc/news/readers.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20131r556166_chk'
  tag severity: 'medium'
  tag gid: 'V-218656'
  tag rid: 'SV-218656r603259_rule'
  tag stig_id: 'GEN006300'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20129r556167_fix'
  tag 'documentable'
  tag legacy: ['V-4275', 'SV-63909']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end

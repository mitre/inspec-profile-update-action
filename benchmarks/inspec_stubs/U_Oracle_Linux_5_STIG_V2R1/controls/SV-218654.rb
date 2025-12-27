control 'SV-218654' do
  title 'The /etc/news/infeed.conf (or equivalent) must have mode 0600 or less permissive.'
  desc 'Excessive permissions on the "" file may allow unauthorized modification which could lead to Denial of Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'The file that corresponds to "/etc/news/hosts.nntp.nolimit" is "/etc/news/infeed.conf". 

Check the permissions for "/etc/news/infeed.conf".

# ls -lL /etc/news/infeed.conf

If "/etc/news/infeed.conf" has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of "/etc/news/infeed.conf" to 0600.

# chmod 0600 /etc/news/infeed.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20129r556160_chk'
  tag severity: 'medium'
  tag gid: 'V-218654'
  tag rid: 'SV-218654r603259_rule'
  tag stig_id: 'GEN006280'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20127r556161_fix'
  tag 'documentable'
  tag legacy: ['V-4274', 'SV-63921']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end

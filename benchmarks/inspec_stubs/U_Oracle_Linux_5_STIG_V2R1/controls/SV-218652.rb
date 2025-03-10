control 'SV-218652' do
  title 'The /etc/news/incoming.conf (or equivalent) must have mode 0600 or less permissive.'
  desc 'Excessive permissions on the "incoming.conf" file may allow unauthorized modification which could lead to Denial-of-Service to authorized users or provide access to unauthorized users.'
  desc 'check', 'The file corresponding to "/etc/news/hosts.nntp" is "/etc/news/incoming.conf". Check the permissions for "/etc/news/incoming.conf".

# ls -lL /etc/news/incoming.conf

If "/etc/news/incoming.conf" has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the "/etc/news/incoming.conf" file to 0600.

# chmod 0600 /etc/news/incoming.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20127r556154_chk'
  tag severity: 'medium'
  tag gid: 'V-218652'
  tag rid: 'SV-218652r603259_rule'
  tag stig_id: 'GEN006260'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20125r556155_fix'
  tag 'documentable'
  tag legacy: ['V-4273', 'SV-63947']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end

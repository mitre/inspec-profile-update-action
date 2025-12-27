control 'SV-218658' do
  title 'The /etc/news/passwd.nntp file (or equivalent) must have mode 0600 or less permissive.'
  desc 'File permissions more permissive than 0600 for "/etc/news/passwd.nntp" may allow access to privileged information by system intruders or malicious users.'
  desc 'check', 'Check "/etc/news/passwd.nntp" permissions:

# ls -lL /etc/news/passwd.nntp

If "/etc/news/passwd.nntp" has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the "/etc/news/passwd.nntp" file.
# chmod 0600 /etc/news/passwd.nntp'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20133r556172_chk'
  tag severity: 'medium'
  tag gid: 'V-218658'
  tag rid: 'SV-218658r603259_rule'
  tag stig_id: 'GEN006320'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20131r556173_fix'
  tag 'documentable'
  tag legacy: ['V-4276', 'SV-63899']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end

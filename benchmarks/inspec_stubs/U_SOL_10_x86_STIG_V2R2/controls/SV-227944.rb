control 'SV-227944' do
  title 'The /etc/news/passwd.nntp file (or equivalent) must have mode 0600 or less permissive.'
  desc 'File permissions more permissive than 0600 for /etc/news/passwd.nntp may allow access to privileged information by system intruders or malicious users.'
  desc 'check', 'Check /etc/news/passwd.nntp permissions.

# ls -lL /etc/news/passwd.nntp

If /etc/news/passwd.nntp has a mode more permissive than 0600,  this is a finding.'
  desc 'fix', 'Change the mode of the /etc/news/passwd.nntp file.
# chmod 0600 /etc/news/passwd.nntp'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30106r490252_chk'
  tag severity: 'medium'
  tag gid: 'V-227944'
  tag rid: 'SV-227944r603266_rule'
  tag stig_id: 'GEN006320'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-30094r490253_fix'
  tag 'documentable'
  tag legacy: ['V-4276', 'SV-4276']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

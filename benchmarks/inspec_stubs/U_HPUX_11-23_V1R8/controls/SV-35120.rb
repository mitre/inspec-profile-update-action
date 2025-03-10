control 'SV-35120' do
  title 'The /etc/news/passwd.nntp file (or equivalent) must have mode 0600 or less permissive.'
  desc 'File permissions more permissive than 0600 for /etc/news/passwd.nntp may allow access to privileged information by system intruders or malicious users.'
  desc 'check', 'Check passwd.nntp permissions.
# find / -type f -name passwd.nntp | xargs -n1 ls -lL

If passwd.nntp has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the passwd.nntp file.

# chmod 0600 <path>/passwd.nntp'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-34978r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4276'
  tag rid: 'SV-35120r1_rule'
  tag stig_id: 'GEN006320'
  tag gtitle: 'GEN006320'
  tag fix_id: 'F-30272r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-37731' do
  title 'The /etc/news/passwd.nntp file (or equivalent) must have mode 0600 or less permissive.'
  desc 'File permissions more permissive than 0600 for "/etc/news/passwd.nntp" may allow access to privileged information by system intruders or malicious users.'
  desc 'fix', 'Change the mode of the "/etc/news/passwd.nntp" file.
# chmod 0600 /etc/news/passwd.nntp'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-4276'
  tag rid: 'SV-37731r1_rule'
  tag stig_id: 'GEN006320'
  tag gtitle: 'GEN006320'
  tag fix_id: 'F-32193r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

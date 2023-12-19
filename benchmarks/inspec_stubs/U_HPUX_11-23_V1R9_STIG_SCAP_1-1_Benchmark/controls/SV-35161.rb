control 'SV-35161' do
  title 'The alias file must be owned by root.'
  desc 'If the aliases file is not owned by root, an unauthorized user may modify the file to add aliases to run malicious code or redirect e-mail.'
  desc 'fix', 'Change the owner of the /etc/mail/aliases file (or equivalent) to root.
# chown root /etc/mail/aliases'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-831'
  tag rid: 'SV-35161r1_rule'
  tag stig_id: 'GEN004360'
  tag gtitle: 'GEN004360'
  tag fix_id: 'F-30308r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

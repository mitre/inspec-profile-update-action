control 'SV-26108' do
  title 'The alias file must not have an extended ACL.'
  desc 'Excessive permissions on the aliases file may permit unauthorized modification.  If the alias file is modified by an unauthorized user, they may modify the file to run malicious code or redirect email.'
  desc 'check', 'Check the permissions of the /etc/mail/aliases file.
# ls -lL /etc/mail/aliases
If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the alias file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27707r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22439'
  tag rid: 'SV-26108r1_rule'
  tag stig_id: 'GEN004390'
  tag gtitle: 'GEN004390'
  tag fix_id: 'F-26287r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

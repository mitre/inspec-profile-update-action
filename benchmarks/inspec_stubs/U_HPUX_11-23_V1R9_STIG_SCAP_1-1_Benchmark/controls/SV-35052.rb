control 'SV-35052' do
  title 'The SSH daemon must restrict login ability to specific users and/or groups.'
  desc 'Restricting SSH logins to a limited group of users, such as system administrators, prevents password guessing and other SSH attacks from reaching system accounts and other accounts not authorized for SSH access.'
  desc 'fix', 'Edit the SSH daemon configuration and add the appropriate keyword directive(s) and space-separated user/group names. The keyword order of precedence is as follows:

DenyUsers, AllowUsers, DenyGroups, AllowGroups'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22470'
  tag rid: 'SV-35052r1_rule'
  tag stig_id: 'GEN005521'
  tag gtitle: 'GEN005521'
  tag fix_id: 'F-30228r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-26763' do
  title 'The SSH daemon must restrict login ability to specific users and/or groups.'
  desc 'Restricting SSH logins to a limited group of users, such as system administrators, prevents password-guessing and other SSH attacks from reaching system accounts and other accounts not authorized for SSH access.'
  desc 'check', "Check the SSH daemon configuration for the AllowGroups setting.
# grep -i AllowGroups /etc/ssh/sshd_config | grep -v '^#' 
If no lines are returned, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration and add an AllowGroups directive.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27772r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22470'
  tag rid: 'SV-26763r1_rule'
  tag stig_id: 'GEN005521'
  tag gtitle: 'GEN005521'
  tag fix_id: 'F-24013r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

control 'SV-226992' do
  title 'The SSH daemon must restrict login ability to specific users and/or groups.'
  desc 'Restricting SSH logins to a limited group of users, such as system administrators, prevents password-guessing and other SSH attacks from reaching system accounts and other accounts not authorized for SSH access.'
  desc 'check', "Check the SSH daemon configuration for the AllowGroups setting.
# grep -i AllowGroups /etc/ssh/sshd_config | grep -v '^#' 
If no lines are returned, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration and add an AllowGroups directive.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29154r485315_chk'
  tag severity: 'medium'
  tag gid: 'V-226992'
  tag rid: 'SV-226992r603265_rule'
  tag stig_id: 'GEN005521'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29142r485316_fix'
  tag 'documentable'
  tag legacy: ['V-22470', 'SV-26763']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

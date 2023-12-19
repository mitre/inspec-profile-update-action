control 'SV-209056' do
  title 'The operating system, upon successful logon, must display to the user the date and time of the last logon or access via ssh.'
  desc 'Users need to be aware of activity that occurs regarding their account. Providing users with information regarding the date and time of their last successful login allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators.

At ssh login, a user must be presented with the last successful login date and time.'
  desc 'check', 'Verify the value associated with the "PrintLastLog" keyword in /etc/ssh/sshd_config:

# grep -i "^PrintLastLog" /etc/ssh/sshd_config

If the "PrintLastLog" keyword is not present, this is not a finding. If the value is not set to "yes", this is a finding.'
  desc 'fix', 'Update the "PrintLastLog" keyword to "yes" in /etc/ssh/sshd_config:

PrintLastLog yes

While it is acceptable to remove the keyword entirely since the default action for the SSH daemon is to print the last login date and time, it is preferred to have the value explicitly documented.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9309r357953_chk'
  tag severity: 'medium'
  tag gid: 'V-209056'
  tag rid: 'SV-209056r793777_rule'
  tag stig_id: 'OL6-00-000507'
  tag gtitle: 'SRG-OS-000025'
  tag fix_id: 'F-9309r357954_fix'
  tag 'documentable'
  tag legacy: ['V-50609', 'SV-64815']
  tag cci: ['CCI-000052']
  tag nist: ['AC-9']
end

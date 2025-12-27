control 'SV-218038' do
  title 'The sendmail package must be removed.'
  desc 'The sendmail software was not developed with security in mind and its design prevents it from being effectively contained by SELinux. Postfix should be used instead.'
  desc 'check', 'Run the following command to determine if the "sendmail" package is installed: 

# rpm -q sendmail


If the package is installed, this is a finding.'
  desc 'fix', 'Sendmail is not the default mail transfer agent and is not installed by default. The "sendmail" package can be removed with the following command: 

# yum erase sendmail'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19519r377129_chk'
  tag severity: 'medium'
  tag gid: 'V-218038'
  tag rid: 'SV-218038r603264_rule'
  tag stig_id: 'RHEL-06-000288'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-19517r377130_fix'
  tag 'documentable'
  tag legacy: ['V-38671', 'SV-50472']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

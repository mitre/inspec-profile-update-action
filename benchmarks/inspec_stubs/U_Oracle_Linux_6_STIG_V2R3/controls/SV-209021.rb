control 'SV-209021' do
  title 'The sendmail package must be removed.'
  desc 'The sendmail software was not developed with security in mind and its design prevents it from being effectively contained by SELinux. Postfix should be used instead.'
  desc 'check', 'Run the following command to determine if the "sendmail" package is installed: 

# rpm -q sendmail

If the package is installed, this is a finding.'
  desc 'fix', 'Sendmail is not the default mail transfer agent and is not installed by default. The "sendmail" package can be removed with the following command: 

# yum erase sendmail'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9274r357848_chk'
  tag severity: 'medium'
  tag gid: 'V-209021'
  tag rid: 'SV-209021r603263_rule'
  tag stig_id: 'OL6-00-000288'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9274r357849_fix'
  tag 'documentable'
  tag legacy: ['V-50881', 'SV-65087']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

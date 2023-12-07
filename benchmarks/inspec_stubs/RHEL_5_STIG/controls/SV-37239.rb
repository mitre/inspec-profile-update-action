control 'SV-37239' do
  title 'Users must not be able to change passwords more than once every 24 hours.'
  desc 'The ability to change passwords frequently facilitates users reusing the same password. This can result in users effectively never changing their passwords.  This would be accomplished by users changing their passwords when required and then immediately changing it to the original value.'
  desc 'fix', 'Change the minimum time period between password changes for each user account to 1 day.
# passwd -n 1 <user name>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-1032'
  tag rid: 'SV-37239r1_rule'
  tag stig_id: 'GEN000540'
  tag gtitle: 'GEN000540'
  tag fix_id: 'F-31186r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end

control 'SV-1032' do
  title 'Users must not be able to change passwords more than once every 24 hours.'
  desc 'The ability to change passwords frequently facilitates users reusing the same password. This can result in users effectively never changing their passwords. This would be accomplished by users changing their passwords when required and then immediately changing it to the original value.'
  desc 'check', "Check the system's configuration to determine if user password changes are permitted more than once every 24 hours.  If this is permitted, this is a finding."
  desc 'fix', 'Configure the system to not allow users to change their passwords more than once every 24 hours.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28013r1_chk'
  tag severity: 'medium'
  tag gid: 'V-27103'
  tag rid: 'SV-1032r2_rule'
  tag stig_id: 'GEN000540'
  tag gtitle: 'GEN000540'
  tag fix_id: 'F-24364r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001266']
  tag nist: ['SI-4 (7) (a)']
end

control 'SV-44879' do
  title 'User passwords must be changed at least every 60 days.'
  desc 'Limiting the lifespan of authenticators limits the period of time an unauthorized user has access to the system while using compromised credentials and reduces the period of time available for password-guessing attacks to run against a single password.'
  desc 'check', 'Check the max days field (the 5th field) of /etc/shadow.
# more /etc/shadow
If the max days field is equal to 0 or greater than 60 for any user, this is a finding.'
  desc 'fix', 'Set the max days field to 60 for all user accounts.
# passwd -x 60 <user>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42333r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11976'
  tag rid: 'SV-44879r1_rule'
  tag stig_id: 'GEN000700'
  tag gtitle: 'GEN000700'
  tag fix_id: 'F-38311r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000180']
  tag nist: ['IA-5 f']
end

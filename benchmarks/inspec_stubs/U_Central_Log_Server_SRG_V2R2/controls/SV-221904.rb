control 'SV-221904' do
  title 'The Central Log Server must enforce the limit of three consecutive invalid logon attempts by a user during a 15 minute time period.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server is configured to lock out the account after 3 consecutive invalid attempts during a 15 minute period.

If the Central Log Server is not configured to lock out the account after 3 consecutive invalid attempts in 15 minutes, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to lock out the account after 3 consecutive invalid attempts during a 15 minute period.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-23619r420054_chk'
  tag severity: 'medium'
  tag gid: 'V-221904'
  tag rid: 'SV-221904r420056_rule'
  tag stig_id: 'SRG-APP-000065-AU-000240'
  tag gtitle: 'SRG-APP-000065'
  tag fix_id: 'F-23608r420055_fix'
  tag 'documentable'
  tag legacy: ['SV-109137', 'V-100033']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end

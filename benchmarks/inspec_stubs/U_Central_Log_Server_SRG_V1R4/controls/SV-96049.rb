control 'SV-96049' do
  title 'The Central Log Server must be configured to prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 

If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to prohibit password reuse for a minimum of five generations.

If the Central Log Server is not configured to prohibit password reuse for a minimum of five generations, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to prohibit password reuse for a minimum of five generations.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-81039r1_chk'
  tag severity: 'low'
  tag gid: 'V-81335'
  tag rid: 'SV-96049r1_rule'
  tag stig_id: 'SRG-APP-000165-AU-002580'
  tag gtitle: 'SRG-APP-000165-AU-002580'
  tag fix_id: 'F-88119r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end

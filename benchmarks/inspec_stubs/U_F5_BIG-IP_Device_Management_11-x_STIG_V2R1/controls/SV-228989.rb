control 'SV-228989' do
  title 'The BIG-IP appliance must be configured to prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 

If the network device allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use a properly configured authentication server that prohibits password reuse for a minimum of five generations. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured for an approved remote authentication server that prohibits password reuse for a minimum of five generations.

If the BIG-IP appliance is not configured to use an associated authentication server that prohibits password reuse for a minimum of five generations, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use a properly configured authentication server to prohibit password reuse for a minimum of five generations.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31304r518012_chk'
  tag severity: 'medium'
  tag gid: 'V-228989'
  tag rid: 'SV-228989r557520_rule'
  tag stig_id: 'F5BI-DM-000109'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31281r518013_fix'
  tag 'documentable'
  tag legacy: ['SV-74579', 'V-60149']
  tag cci: ['CCI-000366', 'CCI-000200']
  tag nist: ['CM-6 b', 'IA-5 (1) (e)']
end

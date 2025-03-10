control 'SV-253538' do
  title 'Prisma Cloud Compute local accounts must enforce strong password requirements.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that must be tested before the password is compromised.

'
  desc 'check', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> Authentication >> Logon tab. 

- If "Token validity period" is greater than 15, this is a finding. 
- If "Enable context sensitive help and single sign on to the Prisma Cloud Support site" is set to "on", this is a finding. 
- If "Disable basic authentication for the API" is set to "off", this is a finding.
- If "Require strong passwords for local accounts" is set to "off", this is a finding.
- If "Require strict certificate validation in Defender installation links" is set to "on", this is a finding.)
  desc 'fix', %q(Navigate to Prisma Cloud Compute Console's >> Manage >> Authentication >>
Logon tab. 

- Set "Token validity period" to 15 or less.
- Set "Enable context sensitive help and single sign on to the Prisma Cloud Support site" to "off".
- Set "Disable basic authentication for the API" to "on".
- Set "Require strong passwords for local accounts" to "on".
- Set "Require strict certificate validation in Defender installation links" to "off".
- Click "Save" and "Restart".)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56990r840450_chk'
  tag severity: 'medium'
  tag gid: 'V-253538'
  tag rid: 'SV-253538r840452_rule'
  tag stig_id: 'CNTR-PC-000640'
  tag gtitle: 'SRG-APP-000164-CTR-000400'
  tag fix_id: 'F-56941r840451_fix'
  tag satisfies: ['SRG-APP-000164-CTR-000400', 'SRG-APP-000166-CTR-000410', 'SRG-APP-000167-CTR-000415', 'SRG-APP-000168-CTR-000420', 'SRG-APP-000169-CTR-000425', 'SRG-APP-000389-CTR-000925', 'SRG-APP-000391-CTR-000935', 'SRG-APP-000400-CTR-000960']
  tag 'documentable'
  tag cci: ['CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-000205', 'CCI-001619', 'CCI-001953', 'CCI-002007', 'CCI-002038']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-2 (12)', 'IA-5 (13)', 'IA-11']
end

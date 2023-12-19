control 'SV-75225' do
  title 'The Google Search Appliance must support DoD requirements to enforce minimum password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password is, the lower the number of possible combinations that need to be tested before the password is compromised. 

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.

Navigate to "Administration", select "User Accounts".

Under "Other Settings" - If "Use strict password checking" is checked, this is not a finding.'
  desc 'fix', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "User Accounts".

Under "Other Settings" - Enable option "Use strict password checking".

Click Save.'
  impact 0.5
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61695r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60773'
  tag rid: 'SV-75225r1_rule'
  tag stig_id: 'GSAP-00-000525'
  tag gtitle: 'SRG-APP-000164'
  tag fix_id: 'F-66453r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end

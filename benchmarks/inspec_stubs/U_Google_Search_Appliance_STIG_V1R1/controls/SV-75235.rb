control 'SV-75235' do
  title 'The Google Search Appliance must support DoD requirements to enforce password complexity by the number of special characters used.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor in determining how long it takes to crack a password. 

The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised. 

Use of a complex password helps to increase the time and resources required to compromise the password.'
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
  tag check_id: 'C-61707r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60783'
  tag rid: 'SV-75235r1_rule'
  tag stig_id: 'GSAP-00-000550'
  tag gtitle: 'SRG-APP-000169'
  tag fix_id: 'F-66465r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end

control 'SV-252601' do
  title 'IBM Aspera Shares must require password complexity features to be enabled.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.'
  desc 'check', 'If the IBM Aspera Shares feature of the Aspera Platform is not installed, this is Not Applicable.

Verify IBM Aspera Shares requires password complexity: 

- Log in to the IBM Aspera Shares web page as a user with administrative privilege. 
- Select the "Admin" tab.
- Scroll down to the "Security" section.
- Select the "User Security" option.
- Verify the "Require strong passwords" option is checked.

If the "Require strong passwords" option is not checked, this is a finding.

If the "Require strong passwords" option is checked, downgrade this requirement to a CAT III.'
  desc 'fix', 'Configure IBM Aspera Shares to require password complexity: 

- Log in to the IBM Aspera Shares web page as a user with administrative privilege. 
- Select the "Admin" tab.
- Scroll down to the "Security" section.
- Select the "User Security" option.
- Put a check the "Require strong passwords" check box.
- Select "Save" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56057r817971_chk'
  tag severity: 'medium'
  tag gid: 'V-252601'
  tag rid: 'SV-252601r817973_rule'
  tag stig_id: 'ASP4-SH-060140'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-56007r817972_fix'
  tag 'documentable'
  tag cci: ['CCI-000192', 'CCI-000193', 'CCI-000194']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)']
end

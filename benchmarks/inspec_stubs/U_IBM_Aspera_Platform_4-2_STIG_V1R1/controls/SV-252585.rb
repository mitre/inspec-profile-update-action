control 'SV-252585' do
  title 'IBM Aspera Faspex passwords must be prohibited from reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to reuse their password consecutively when that password has exceeded its defined lifetime, the end result is a password that is not changed per policy requirements.'
  desc 'check', 'If the IBM Aspera Faspex feature of the Aspera Platform is not installed, this is Not Applicable.

Verify IBM Aspera Faspex passwords are prohibited from reuse for a minimum of five generations: 

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege. 
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section.
- Verify the "Faspex accounts" "Prevent passwords reuse" option is checked.
- Verify the "Faspex accounts" "Prevent passwords reuse" options is set to "5" or more.

If the "Prevent passwords reuse" options is less than "5" or the option is not checked, this is a finding.'
  desc 'fix', 'Configure IBM Aspera Faspex passwords to be prohibited from reuse for a minimum of five generations: 

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege. 
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section.
- Put a check the "Faspex accounts" "Prevent passwords reuse" check box.
- Edit the "Faspex accounts" "Prevent passwords reuse" option to "5" or more.
- Select "Update" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56041r817923_chk'
  tag severity: 'medium'
  tag gid: 'V-252585'
  tag rid: 'SV-252585r817925_rule'
  tag stig_id: 'ASP4-FA-050210'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-55991r817924_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end

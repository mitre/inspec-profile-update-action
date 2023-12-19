control 'SV-252567' do
  title 'IBM Aspera Console passwords must be prohibited from reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to reuse their password consecutively when that password has exceeded its defined lifetime, the end result is a password that is not changed per policy requirements.'
  desc 'check', 'Verify IBM Aspera Console passwords are prohibited from reuse for a minimum of five generations: 

- Log in to the IBM Aspera Console web page as a user with administrative privilege. 
- Select the "Configuration" tab.
- Select the "Defaults" tab.
- Scroll down to the "Console Password Options" section.
- Verify the "Password Expiration" option is checked.
- Verify the "Password Reuse Limit" option is set to "5" or more.

If the "Password Expiration" option is not checked, this is a finding.

If the "Password Reuse Limit" is set to less than "5" or is set to "0", this is a finding.'
  desc 'fix', 'Configure IBM Aspera Console passwords to be prohibited from reuse for a minimum of five generations: 

- Log in to the IBM Aspera Console web page as a user with administrative privilege. 
- Select the "Configuration" tab.
- Select the "Defaults" tab.
- Scroll down to the "Console Password Options" section.
- Put a check in the "Password Expiration" check box.
- Edit the "Password Reuse Limit" option to "5" or more.
 Note: "0" disables the "Password Reuse Limit" option.
- Select "Save" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56023r817869_chk'
  tag severity: 'medium'
  tag gid: 'V-252567'
  tag rid: 'SV-252567r817871_rule'
  tag stig_id: 'ASP4-CS-040200'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-55973r817870_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end

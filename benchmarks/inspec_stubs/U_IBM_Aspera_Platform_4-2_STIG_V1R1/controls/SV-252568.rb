control 'SV-252568' do
  title 'IBM Aspera Console user account passwords must have a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the Aspera system does not limit the lifetime of passwords and force users to change update them, there is a risk passwords could be compromised.'
  desc 'check', 'Verify IBM Aspera Console user account passwords have a 60-day maximum password lifetime restriction: 

- Log in to the IBM Aspera Console web page as a user with administrative privilege. 
- Select the "Configuration" tab.
- Select the "Defaults" tab.
- Scroll down to the "Console Password Options" section.
- Verify the "Password Expiration" option is checked.
- Verify the "Password Duration" option is set to "60" days or less.

If the "Password Expiration" option is not checked, this is a finding.

If the "Password Duration" is set to more than "60" days or is set to "0", this is a finding.'
  desc 'fix', 'Configure IBM Aspera Console user account passwords to have a 60-day maximum password lifetime restriction: 

- Log in to the IBM Aspera Console web page as a user with administrative privilege. 
- Select the "Configuration" tab.
- Select the "Defaults" tab.
- Scroll down to the "Console Password Options" section.
- Put a check in the "Password Expiration" check box.
- Edit the "Password Duration" option to "60" days or less.
 Note: "0" disables the "Password Duration" option.
- Select "Save" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56024r817872_chk'
  tag severity: 'medium'
  tag gid: 'V-252568'
  tag rid: 'SV-252568r817874_rule'
  tag stig_id: 'ASP4-CS-040210'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-55974r817873_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end

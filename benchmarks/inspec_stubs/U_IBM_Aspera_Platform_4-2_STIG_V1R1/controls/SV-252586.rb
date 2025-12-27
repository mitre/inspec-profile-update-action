control 'SV-252586' do
  title 'IBM Aspera Faspex user account passwords must have a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the Aspera system does not limit the lifetime of passwords and force users to change update them, there is a risk passwords could be compromised.'
  desc 'check', 'If the IBM Aspera Faspex feature of the Aspera Platform is not installed, this is Not Applicable.

Verify IBM Aspera Faspex user account passwords have a 60-day maximum password lifetime restriction: 

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege. 
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section.
- Verify the "Faspex accounts" "Passwords expire" option is checked.
- Verify the "Faspex accounts" "Passwords expire" options is set to "60" days or less.

If the "Passwords expire" options is set to more than "60" days or the option is not checked, this is a finding.'
  desc 'fix', 'Configure IBM Aspera Faspex user account passwords to have a 60-day maximum password lifetime restriction: 

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege. 
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section.
- Put a check the "Faspex accounts" "Passwords expire" check box.
- Edit the "Faspex accounts" "Passwords expire" option to "60" days or less.
- Select "Update" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56042r817926_chk'
  tag severity: 'medium'
  tag gid: 'V-252586'
  tag rid: 'SV-252586r817928_rule'
  tag stig_id: 'ASP4-FA-050220'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-55992r817927_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end

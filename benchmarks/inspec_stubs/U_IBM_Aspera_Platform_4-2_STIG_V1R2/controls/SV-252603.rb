control 'SV-252603' do
  title 'IBM Aspera Shares user account passwords must have a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the Aspera system does not limit the lifetime of passwords and force users to change update them, there is a risk passwords could be compromised.'
  desc 'check', 'If the IBM Aspera Shares feature of the Aspera Platform is not installed, this is Not Applicable.

Verify IBM Aspera Shares user account passwords have a 60-day maximum password lifetime restriction: 

- Log in to the IBM Aspera Shares web page as a user with administrative privilege. 
- Select the "Admin" tab.
- Scroll down to the "Security" section.
- Select the "User Security" option.
- Verify the "Password expiration interval" is set to "60" or less.

If the "Password expiration interval" is greater than "60" or is blank, this is a finding.'
  desc 'fix', 'Configure IBM Aspera Shares user account passwords to have a 60-day maximum password lifetime restriction: 

- Log in to the IBM Aspera Shares web page as a user with administrative privilege. 
- Select the "Admin" tab.
- Scroll down to the "Security" section.
- Select the "User Security" option.
- Edit the "Password expiration interval" to "60" days or less.
- Select "Save" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56059r817977_chk'
  tag severity: 'medium'
  tag gid: 'V-252603'
  tag rid: 'SV-252603r817979_rule'
  tag stig_id: 'ASP4-SH-060160'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-56009r817978_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end

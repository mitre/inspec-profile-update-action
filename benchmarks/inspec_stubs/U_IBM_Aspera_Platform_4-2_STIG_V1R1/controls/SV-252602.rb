control 'SV-252602' do
  title 'IBM Aspera Shares must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Lack of authentication enables anyone to gain access to the network or possibly a network element that provides opportunity for intruders to compromise resources within the network infrastructure. By identifying and authenticating non-organizational users, their access to network resources can be restricted accordingly.

IBM Aspera Faspex external users must register for an account and be authenticated before downloading a package. This authentication is conducted by the IBM Aspera Faspex server using password authentication.'
  desc 'check', 'If the IBM Aspera Shares feature of the Aspera Platform is not installed, this is Not Applicable.

To ensure that all external recipients of Shares packages must register for an account before they can download packages or files within packages: 

- Log in to the IBM Aspera Shares web page as a user with administrative privilege. 
- Select the "Admin" tab.
- Scroll down to the "Security" section.
- Select the "User Security" option from the left menu.
- Verify that the "Self Registration" option is set to "Moderated" or "None".

If the "Self Registration" option is set to "Unmoderated", this is a finding.'
  desc 'fix', 'To configure Aspera Shares to authenticate all external recipients of Shares packages before they can download packages or files within packages: 

- Log in to the IBM Aspera Shares web page as a user with administrative privilege. 
- Select the "Admin" tab.
- Scroll down to the "Security" section.
- Select the "User Security" option from the left menu.
- Use the dropdown menu to set the "Self Registration" option to "Moderated" or "None".
- Select "Save" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56058r817974_chk'
  tag severity: 'medium'
  tag gid: 'V-252602'
  tag rid: 'SV-252602r817976_rule'
  tag stig_id: 'ASP4-SH-060150'
  tag gtitle: 'SRG-NET-000169-ALG-000102'
  tag fix_id: 'F-56008r817975_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end

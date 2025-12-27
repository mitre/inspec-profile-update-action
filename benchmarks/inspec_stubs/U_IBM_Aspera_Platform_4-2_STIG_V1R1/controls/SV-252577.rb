control 'SV-252577' do
  title 'IBM Aspera Faspex must allow the use of a temporary password for logins with an immediate change to a permanent password.'
  desc 'Without providing this capability, an account may be created without a password. Non-repudiation cannot be guaranteed once an account is created if a user is not forced to change the temporary password upon initial login.

Temporary passwords are typically used to allow access when new accounts are created or passwords are changed. It is common practice for administrators to create temporary passwords for user accounts which allow the users to log in, yet force them to change the password once they have successfully authenticated.'
  desc 'check', 'If the IBM Aspera Faspex feature of the Aspera Platform is not installed, this is Not Applicable.

Verify IBM Aspera Faspex allows the use of a temporary password for logins with an immediate change to a permanent password: 

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege. 
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section.
- Verify the "Require new users to change password on first login" option is checked.

If the "Require new users to change password on first login" option is not checked, this is a finding.'
  desc 'fix', 'Configure IBM Aspera Faspex to allow the use of a temporary password for logins with an immediate change to a permanent password: 

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege. 
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" section.
- Put a check in the "Require new users to change password on first login" option check box.
- Select "Update" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56033r817899_chk'
  tag severity: 'medium'
  tag gid: 'V-252577'
  tag rid: 'SV-252577r817901_rule'
  tag stig_id: 'ASP4-FA-050120'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-55983r817900_fix'
  tag 'documentable'
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end

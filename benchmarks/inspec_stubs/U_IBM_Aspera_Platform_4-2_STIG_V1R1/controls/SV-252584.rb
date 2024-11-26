control 'SV-252584' do
  title 'IBM Aspera Faspex must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Lack of authentication enables anyone to gain access to the network or possibly a network element that provides opportunity for intruders to compromise resources within the network infrastructure. By identifying and authenticating non-organizational users, their access to network resources can be restricted accordingly.

IBM Aspera Faspex external users must register for an account and be authenticated before downloading a package. This authentication is conducted by the IBM Aspera Faspex server using password authentication.'
  desc 'check', 'If the IBM Aspera Faspex feature of the Aspera Platform is not installed, this is Not Applicable.

To ensure that all external recipients of Faspex packages must register for an account before they can download packages or files within packages: 

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege. 
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" option from the left menu.
- Verify that the option "Require external users to register" is checked.

If this option is not checked, this is a finding.

Also ensure IBM Aspera Faspex is configured for "Moderated" self-registration when permitting use by external users. To do this, verify the "Moderated" option is selected from the picklist for "Self registration" under the Registrations heading. 

If this option is not checked, this is a finding.'
  desc 'fix', 'To configure Aspera Faspex to authenticate all external recipients of Faspex packages before they can download packages or files within packages: 

- Log in to the IBM Aspera Faspex web page as a user with administrative privilege. 
- Select the "Server" tab.
- Select the "Configuration" tab.
- Select the "Security" option from the left menu.
- Check the option "Require external users to register" under the "Registrations" heading.
- Select the "Moderated" option from the picklist for "Self registration" under the Registrations heading.
- Select "Update" at the bottom of the page.'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56040r817920_chk'
  tag severity: 'medium'
  tag gid: 'V-252584'
  tag rid: 'SV-252584r818985_rule'
  tag stig_id: 'ASP4-FA-050200'
  tag gtitle: 'SRG-NET-000169-ALG-000102'
  tag fix_id: 'F-55990r817921_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end

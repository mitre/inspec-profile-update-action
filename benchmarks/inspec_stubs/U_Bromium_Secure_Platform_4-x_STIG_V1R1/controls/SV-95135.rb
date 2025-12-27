control 'SV-95135' do
  title 'The Bromium Enterprise Controller (BEC) must protect the BEC Web Console from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

The BEC Web console can gives a view of events, threat conditions, policies, and client information and thus is considered an audit tool. BEC does not allow the integration of other audit tool provided by third-party vendors. The BEC Web console access is configured in Settings >> Users.'
  desc 'check', 'Obtain a list of authorized BEC Web console users from the site representative. Verify only these users are configured for access.

1. From the BEC console, click on "Settings".  
2. View the list of Users.  

If unauthorized users are listed in the BEC Web console, this is a finding.'
  desc 'fix', 'Configure BEC Web console access to permit only authorized users.

1. From the BEC console, click on "Settings".  
2. Select "Users".  
3. Click User Options >> Add User.  
4. Add new user and their Active Directory details, and assign new user to a Group using the drop-down list.'
  impact 0.5
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80103r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80431'
  tag rid: 'SV-95135r1_rule'
  tag stig_id: 'BROM-00-000245'
  tag gtitle: 'SRG-APP-000121'
  tag fix_id: 'F-87237r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end

control 'SV-83795' do
  title 'The NSX vCenter must reveal error messages only to authorized individuals (ISSO, ISSM, and SA).'
  desc "Only authorized personnel must be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state. Additionally, sensitive account information must not be revealed through error messages to unauthorized personnel or their designated representatives."
  desc 'check', 'Verify the application must reveal error messages only to authorized individuals.

Log on to vSphere Web Client with credentials authorized for administration, navigate and select Networking and Security >> NSX Managers >> NSX Manager in the Name column >> Manage tab >> Users. 

View each role and verify the users and/or groups assigned to it.

Application service account and user required privileges must be documented.

If any user or service account has more privileges than required, this is a finding.'
  desc 'fix', 'To create a new role with specific permissions, associate the newly created role to an Active Directory group, and associate that group to an NSX Role, do the following:

Log on to vSphere Web Client with credentials authorized for administration, navigate and select Administration >> Access Control >> Roles >> Click the green plus sign, enter a name for the role, and select only the specific permissions required. Groups can then be assigned to the newly created role. 

To associate the newly created role to an Active Directory Group, navigate and select Administration >> Access Control >> Global Permissions >> Click the green plus sign >> Click Add under Users and Groups >> Select the appropriate Group and assign the appropriate role. 

Navigate and select Networking and Security >> NSX Managers >> NSX Manager in the Name column >> Manage tab >> Users >> Click the green plus sign >> Choose Specify a vCenter group, enter FQDN of group name, click Next >> Select the appropriate NSX Role and click Finish.

Application service account and user required privileges must be documented.'
  impact 0.5
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69631r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69191'
  tag rid: 'SV-83795r1_rule'
  tag stig_id: 'VNSX-ND-000077'
  tag gtitle: 'SRG-APP-000267-NDM-000273'
  tag fix_id: 'F-75377r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end

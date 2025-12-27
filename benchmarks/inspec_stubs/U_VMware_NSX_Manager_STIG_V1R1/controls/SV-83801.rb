control 'SV-83801' do
  title 'The NSX vCenter must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges. 
 
Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations.'
  desc 'check', 'Verify that non-privileged users are prevented from executing privileged functions, including disabling, circumventing, or altering implemented security safeguards/countermeasures.

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
  tag check_id: 'C-69637r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69197'
  tag rid: 'SV-83801r1_rule'
  tag stig_id: 'VNSX-ND-000092'
  tag gtitle: 'SRG-APP-000340-NDM-000288'
  tag fix_id: 'F-75383r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end

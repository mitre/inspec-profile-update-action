control 'SV-83767' do
  title 'The NSX vCenter must enforce the assigned privilege level for each administrator and authorizations for access to all commands relative to the privilege level in accordance with applicable policy for the device.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Network devices use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'Verify the assigned privilege level for each administrator and authorizations for access to all commands relative to the privilege level in accordance with applicable policy for the device.

Log on to vSphere Web Client with credentials authorized for administration, navigate and select Networking and Security >> NSX Managers >> NSX Manager in the Name column >> Manage tab >> Users. 

View each role and verify the users and/or groups assigned to it.

Application service account and user required privileges must be documented.

If any user or service account has more privileges than required, this is a finding.'
  desc 'fix', 'To create a new role with specific permissions, associate the newly created role to an Active Directory group, and associate that group to an NSX Role, do the following:

Log on to vSphere Web Client with credentials authorized for administration, navigate and select Administration >> Access Control >> Roles >> Click the green plus sign and enter a name for the role and select only the specific permissions required. Groups can then be assigned to the newly created role. 

To associate the newly created role to an Active Directory Group, navigate and select Administration >> Access Control >> Global Permissions >> Click the green plus sign >> Click Add under Users and Groups >> Select the appropriate Group and assign the appropriate role. 

Navigate and select Networking and Security >> NSX Managers >> NSX Manager in the Name column >> Manage tab >> Users >> Click the green plus sign >> Choose Specify a vCenter group, enter FQDN of group name, click Next >> Select the appropriate NSX Role and click Finish.

Application service account and user required privileges must be documented.'
  impact 0.7
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69601r1_chk'
  tag severity: 'high'
  tag gid: 'V-69163'
  tag rid: 'SV-83767r1_rule'
  tag stig_id: 'VNSX-ND-000013'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-75349r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end

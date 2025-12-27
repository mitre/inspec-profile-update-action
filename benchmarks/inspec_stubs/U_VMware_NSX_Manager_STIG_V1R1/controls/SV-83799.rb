control 'SV-83799' do
  title 'If the NSX vCenter uses role-based access control, the network device must enforce organization-defined role-based access control policies over defined subjects and objects.'
  desc 'Organizations can create specific roles based on job functions and the authorizations (i.e., privileges) to perform needed operations on organizational information systems associated with the organization-defined roles. When administrators are assigned to the organizational roles, they inherit the authorizations or privileges defined for those roles. RBAC simplifies privilege administration for organizations because privileges are not assigned directly to every administrator (which can be a significant number of individuals for mid- to large-size organizations) but are instead acquired through role assignments. RBAC can be implemented either as a mandatory or discretionary form of access control.
 
The RBAC policies and the subjects and objects are defined uniquely for each network device, so they cannot be specified in the requirement.'
  desc 'check', 'Verify role-based access control. The network device must enforce organization-defined role-based access control policies over defined subjects and objects.

Log on to vSphere Web Client with credentials authorized for administration, navigate and select Networking and Security >> NSX Managers >> NSX Manager in the Name column >> Manage tab >> Users. 

View each role and verify the users and/or groups assigned to it.

Application service account and user required privileges must be documented.

If any user or service account has more privileges than required, this is a finding.'
  desc 'fix', 'To create a new role with specific permissions, associate the newly created role to an Active Directory group, and associate that group to an NSX Role, do the following:

Log on to vSphere Web Client with credentials authorized for administration, navigate and select Administration >> Access Control >> Roles >> Click the green plus sign and enter a name for the role and select only the specific permissions required. Groups can then be assigned to the newly created role. 

To associate the newly created role to an Active Directory Group, navigate and select Administration >> Access Control >> Global Permissions >> Click the green plus sign >> Click Add under Users and Groups >> Select the appropriate Group and assign the appropriate role. 

Navigate and select Networking and Security >> NSX Managers >> NSX Manager in the Name column >> Manage tab >> Users >> Click the green plus sign >> Choose Specify a vCenter group, enter FQDN of group name, click Next >> Select the appropriate NSX Role and click Finish.

Application service account and user required privileges must be documented.'
  impact 0.5
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69635r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69195'
  tag rid: 'SV-83799r1_rule'
  tag stig_id: 'VNSX-ND-000091'
  tag gtitle: 'SRG-APP-000329-NDM-000287'
  tag fix_id: 'F-75381r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002169']
  tag nist: ['CM-6 b', 'AC-3 (7)']
end

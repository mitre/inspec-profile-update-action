control 'SV-83805' do
  title 'The NSX vCenter must provide the capability for organization-identified individuals or roles to change the auditing to be performed based on all selectable event criteria within near-real time.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to effectively respond, and important forensic information may be lost.
 
This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting. Organizations can establish time thresholds in which audit actions are changed, for example, near-real-time, within minutes, or within hours.'
  desc 'check', 'Verify the capability for organization-identified individuals or roles to change the auditing to be performed based on all selectable event criteria within near-real time.

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
  tag check_id: 'C-69641r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69201'
  tag rid: 'SV-83805r1_rule'
  tag stig_id: 'VNSX-ND-000096'
  tag gtitle: 'SRG-APP-000353-NDM-000292'
  tag fix_id: 'F-75387r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end

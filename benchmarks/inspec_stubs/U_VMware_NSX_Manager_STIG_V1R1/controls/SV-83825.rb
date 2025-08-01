control 'SV-83825' do
  title 'The NSX vCenter must accept multifactor credentials.'
  desc 'DoD has mandated the use of the CAC to support identity management and personal authentication for systems covered under HSPD 12, as well as a primary component of layered protection for national security systems.'
  desc 'check', 'Verify the Windows server hosting vCenter is joined to the domain and configured for Single Sign-On Identity Source of the Active Directory domain. Access to vCenter must be is done using Active Directory/CAC/PIV certificate accounts. CAC/PIV certificate must be mapped to a privileged Active Directory account and the Windows platform client running the web browser must be CAC/PIV-enabled and must not have external network access.

If the vCenter server is not joined to an Active Directory domain and not configured for Single Sign-On Identity Source of the Active Directory domain, and Active Directory/CAC/PIV certificate-based accounts are not used for daily operations of the vCenter server, this is a finding.'
  desc 'fix', 'If local accounts are used for normal operations, Active Directory user accounts/groups must be created and then associated appropriately for normal operations. To create a new role with specific permissions, associate the newly created role to an Active Directory group, and associate that group to an NSX Role, do the following:

Log on to vSphere Web Client with credentials authorized for administration, navigate and select Administration >> Access Control >> Roles >> Click the green plus sign, enter a name for the role, and select only the specific permissions required. Groups can then be assigned to the newly created role. 

To associate the newly created role to an Active Directory Group, navigate and select Administration >> Access Control >> Global Permissions >> Click the green plus sign >> Click Add under Users and Groups >> Select the appropriate Group and assign the appropriate role. 

Navigate and select Networking and Security >> NSX Managers >> NSX Manager in the Name column >> Manage tab >> Users >> Click the green plus sign >> Choose Specify a vCenter group, enter FQDN of group name, click Next >> Select the appropriate NSX Role and click Finish.

All local windows accounts must be removed from the vCenter and Windows server.

Application service account and user required privileges must be documented.'
  impact 0.5
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69661r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69221'
  tag rid: 'SV-83825r1_rule'
  tag stig_id: 'VNSX-ND-000142'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-75407r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

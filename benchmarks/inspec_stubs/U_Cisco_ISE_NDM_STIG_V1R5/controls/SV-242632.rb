control 'SV-242632' do
  title 'The Cisco ISE must enforce access restrictions associated with changes to the firmware, OS, and hardware components.'
  desc 'Changes to the hardware or software components of the network device can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals should be allowed administrative access to the network device for implementing any changes or upgrades. This requirement applies to updates of the application files, configuration, ACLs, and policy filters.

RBAC policies determine if an administrator can be granted a specific type of access to a menu item or other identity group data elements. You can grant or deny access to a menu item or identity group data element to an administrator based on the admin group, by using RBAC policies. When administrators log in to the Admin portal, they can access menus and data that are based on the policies and permissions defined for the admin groups with which they are associated.

RBAC policies map admin groups to menu access and data access permissions. For example, you can prevent Access operations menu and the policy data elements. This can be achieved by creating a custom RBAC policy for the admin group with which that network administrator is associated.'
  desc 'check', 'Determine if groups with access such as Helpdesk Admin, Network Device Admin, SuperAdmin, and System Admin (at a minimum) are assigned unauthorized users.

1. Choose Administration >> System >> Admin Access >> Administrators >> Admin Groups.
2. Review the users for the groups with edit access such as Helpdesk Admin, Network Device Admin, SuperAdmin, and System Admin at a minimum.

If the Cisco ISE does not enforce access restrictions associated with changes to the firmware, OS, and hardware components, this is a finding.'
  desc 'fix', '1. Choose Administration >> System >> Admin Access >> Administrators >> Admin Groups.
2. Review the users for the groups with edit access such as Helpdesk Admin, Network Device Admin, SuperAdmin, and System Admin at a minimum.
3. To delete users from the admin group, check the check box corresponding to the user that you want to delete, and click "Remove".
4. Click "Submit".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45907r714204_chk'
  tag severity: 'medium'
  tag gid: 'V-242632'
  tag rid: 'SV-242632r879887_rule'
  tag stig_id: 'CSCO-NM-000260'
  tag gtitle: 'SRG-APP-000516-NDM-000335'
  tag fix_id: 'F-45864r714205_fix'
  tag 'documentable'
  tag cci: ['CCI-000345', 'CCI-000366']
  tag nist: ['CM-5', 'CM-6 b']
end

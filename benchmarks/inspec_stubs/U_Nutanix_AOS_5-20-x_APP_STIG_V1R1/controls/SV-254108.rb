control 'SV-254108' do
  title 'Nutanix AOS must enforce access restrictions associated with changes to application server configuration.'
  desc "When dealing with access restrictions pertaining to change control, it should be noted that any changes to the software, and/or application server configuration can potentially have significant effects on the overall security of the system.

Access restrictions for changes also include application software libraries.

If the application server provides automatic code deployment capability, (where updates to applications hosted on the application server are automatically performed, usually by the developers' IDE tool), it must also provide a capability to restrict the use of automatic application deployment. Automatic code deployments are allowable in a development environment, but not in production."
  desc 'check', 'Confirm Nutanix Prism Elements is setup with Role Based Access Controls.

1. Log in into Nutanix Prism Elements.
2. Select the gear icon on top right corner.
3. Select "Authentication" from left navigation pane.
If no Organizational approved Directory (AD/LDAP) is listed, this is a finding.

4. Select "Role Mapping".
If no Role mappings are listed, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS Prism Elements to use Role Base Access Control with an Organization approved Directory (AD, LDAP).

1. Log in into Nutanix Prism Elements.
2. Select the gear icon on top right corner.
3. Select "Authentication" from left navigation pane.
4. Add an authenticated Organization approved Directory. 
5. Setup Role Mappings for Users and or Groups.'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57593r858121_chk'
  tag severity: 'medium'
  tag gid: 'V-254108'
  tag rid: 'SV-254108r858121_rule'
  tag stig_id: 'NUTX-AP-000220'
  tag gtitle: 'SRG-APP-000380-AS-000088'
  tag fix_id: 'F-57544r846411_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end

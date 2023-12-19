control 'SV-80777' do
  title 'The HP FlexFabric Switch must enforce access restrictions associated with changes to the system components.'
  desc 'Changes to the hardware or software components of the HP FlexFabric Switch can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals should be allowed administrative access to the HP FlexFabric Switch for implementing any changes or upgrades. This requirement applies to updates of the application files, configuration, ACLs, and policy filters.'
  desc 'check', 'Check the HP FlexFabric Switch to determine if only authorized administrators have permissions for changes, deletions and updates on HP FlexFabric Switch.

[HP] display local-user

Device management user user1:
 State:                    Active
 Service type:             SSH
 User group:               system
 Bind attributes:
 Authorization attributes:
  Work directory:          flash:
  User role list:          role1

[HP] display role

Role: role1
  Description:
  VLAN policy: deny
  Permitted VLANs: 10 to 20
  Interface policy: permit (default)
  VPN instance policy: permit (default)
  -------------------------------------------------------------------
  Rule    Perm   Type  Scope         Entity
  -------------------------------------------------------------------
  1       permit R--   feature       -
  2       permit       command       system-view ; vlan *
  R:Read W:Write X:Execute

If unauthorized users are allowed to change the hardware or software, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to enforce access restrictions associated with changes to the system components. 

Below is an example how to configure a user-role and assign it to a user:

Create the user role role1: 

[HP] role name role1

Configure rule 1 to permit the user role to access read commands of all features: 

[HP-role-role1] rule 1 permit read feature

Configure rule 2 to permit the user role to create VLANs and access commands in VLAN view: 

[HP-role-role1] rule 2 permit command system-view ; vlan *

Change the VLAN policy to permit the user role to configure only VLANs 10 to 20: 

[HP-role-role1] vlan policy deny
[HP-role-role1-vlanpolicy] permit vlan 10 to 20
[HP-role-role1-vlanpolicy] quit
[HP-role-role1] quit

Create a management local user named user1 and enter its view: 

[HP] local-user user1 class manage

Set a password for the user: 

[HP-luser-manage-user1] password simple xxxxxx

Set the service type to SSH: 

[HP-luser-manage-user1] service-type ssh

Assign role1 to the user: 

[HP-luser-manage-user1] authorization-attribute user-role role1

To make sure that the user has only the permissions of role1, remove the user from the default user role network-operator: 

[HP-luser-manage-user1] undo authorization-attribute user-role network-operator
[HP-luser-manage-user1] quit'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66933r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66287'
  tag rid: 'SV-80777r1_rule'
  tag stig_id: 'HFFS-ND-000132'
  tag gtitle: 'SRG-APP-000516-NDM-000335'
  tag fix_id: 'F-72363r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000345', 'CCI-000366']
  tag nist: ['CM-5', 'CM-6 b']
end

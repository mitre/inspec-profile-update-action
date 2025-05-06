control 'SV-80755' do
  title 'If the HP FlexFabric Switch uses mandatory access control, the HP FlexFabric Switch must enforce organization-defined mandatory access control policies over all subjects and objects.'
  desc 'Mandatory access control policies constrain what actions subjects can take with information obtained from data objects for which they have already been granted access, thus preventing the subjects from passing the information to unauthorized subjects and objects. This class of mandatory access control policies also constrains what actions subjects can take with respect to the propagation of access control privileges; that is, a subject with a privilege cannot pass that privilege to other subjects.

Enforcement of mandatory access control is typically provided via an implementation that meets the reference monitor concept. The reference monitor enforces (mediates) access relationships between all subjects and objects based on privilege and need to know.

The mandatory access control policies are defined uniquely for each network device, so they cannot be specified in the requirement. An example of where mandatory access control may be needed is to prevent administrators from tampering with audit objects.'
  desc 'check', 'Check the HP FlexFabric Switch to determine if organization-defined mandatory access control policies are enforced over all subjects and objects.

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

If organization-defined mandatory access control policies are not enforced over all subjects and objects, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to enforce organization-defined mandatory access control policies over all subjects and objects. Below is an example how to configure a user-role and assign it to a user:

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
  tag check_id: 'C-66911r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66265'
  tag rid: 'SV-80755r1_rule'
  tag stig_id: 'HFFS-ND-000119'
  tag gtitle: 'SRG-APP-000491-NDM-000316'
  tag fix_id: 'F-72341r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-003014']
  tag nist: ['CM-6 b', 'AC-3 (3)']
end

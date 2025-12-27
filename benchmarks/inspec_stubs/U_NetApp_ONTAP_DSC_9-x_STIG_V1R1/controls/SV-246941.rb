control 'SV-246941' do
  title 'ONTAP must be configured to enforce organization-defined mandatory access control policies over all subjects and objects.'
  desc 'Mandatory access control policies constrain what actions subjects can take with information obtained from data objects for which they have already been granted access, thus preventing the subjects from passing the information to unauthorized subjects and objects. This class of mandatory access control policies also constrains what actions subjects can take with respect to the propagation of access control privileges; that is, a subject with a privilege cannot pass that privilege to other subjects.

Enforcement of mandatory access control is typically provided via an implementation that meets the reference monitor concept. The reference monitor enforces (mediates) access relationships between all subjects and objects based on privilege and need to know.

The mandatory access control policies are defined uniquely for each network device, so they cannot be specified in the requirement. An example of where mandatory access control may be needed is to prevent administrators from tampering with audit objects.'
  desc 'check', 'Use "security login show" to see all configured users and their roles. Use "security login role show" to see specific commands allowed for each role.

If ONTAP cannot be configured to enforce organization-defined mandatory access control policies over all subjects and objects, this is a finding.'
  desc 'fix', 'Configure roles with "security login role create -role <name>" to create new roles, and "security login create -user-or-group-name <user_name> -role <name>" to assign the role to a specific user or group.'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50373r769153_chk'
  tag severity: 'medium'
  tag gid: 'V-246941'
  tag rid: 'SV-246941r769155_rule'
  tag stig_id: 'NAOT-CM-000004'
  tag gtitle: 'SRG-APP-000491-NDM-000316'
  tag fix_id: 'F-50327r769154_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-003014']
  tag nist: ['CM-6 b', 'AC-3 (3)']
end

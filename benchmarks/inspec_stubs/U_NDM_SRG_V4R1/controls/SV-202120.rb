control 'SV-202120' do
  title 'If the network device uses mandatory access control, the network device must enforce organization-defined mandatory access control policies over all subjects and objects.'
  desc 'Mandatory access control policies constrain what actions subjects can take with information obtained from data objects for which they have already been granted access, thus preventing the subjects from passing the information to unauthorized subjects and objects. This class of mandatory access control policies also constrains what actions subjects can take with respect to the propagation of access control privileges; that is, a subject with a privilege cannot pass that privilege to other subjects.

Enforcement of mandatory access control is typically provided via an implementation that meets the reference monitor concept. The reference monitor enforces (mediates) access relationships between all subjects and objects based on privilege and need to know.

The mandatory access control policies are defined uniquely for each network device, so they cannot be specified in the requirement. An example of where mandatory access control may be needed is to prevent administrators from tampering with audit objects.'
  desc 'check', 'Check the network device to determine if organization-defined mandatory access control policies are enforced over all subjects and objects. If it does not use mandatory access control, this is not a finding.

If organization-defined mandatory access control policies are not enforced over all subjects and objects, this is a finding.'
  desc 'fix', 'Configure the network device to enforce organization-defined mandatory access control policies over all subjects and objects.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2246r382040_chk'
  tag severity: 'medium'
  tag gid: 'V-202120'
  tag rid: 'SV-202120r400750_rule'
  tag stig_id: 'SRG-APP-000491-NDM-000316'
  tag gtitle: 'SRG-APP-000491'
  tag fix_id: 'F-2247r382041_fix'
  tag 'documentable'
  tag legacy: ['SV-69517', 'V-55271']
  tag cci: ['CCI-003014', 'CCI-000366']
  tag nist: ['AC-3 (3)', 'CM-6 b']
end

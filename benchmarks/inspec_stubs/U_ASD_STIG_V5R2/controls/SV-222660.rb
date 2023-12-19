control 'SV-222660' do
  title 'Procedures must be in place to notify users when an application is decommissioned.'
  desc 'When maintenance no longer exists for an application, there are no individuals responsible for making security updates. The application support staff should maintain procedures for decommissioning. The decommissioning process should include notifying users of the pending decommissioning event. If the users are not informed of the decommissioning event, attackers may be able to stand up similar looking system and fool users into attempting to log onto a duplicate system. This can be as simple as a banner informing users.

This risk is primarily geared towards insider threat scenarios and externally accessible applications that provide access to publicly releasable data but should also be applied to internal systems as a best practice.'
  desc 'check', 'Interview the application representative to determine if provisions are in place to notify users when an application is decommissioned.
 
If provisions are not in place to notify users when an application is decommissioned, this is a finding.'
  desc 'fix', 'Create and establish procedures to notify users when an application is decommissioned.'
  impact 0.3
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24330r493888_chk'
  tag severity: 'low'
  tag gid: 'V-222660'
  tag rid: 'SV-222660r864442_rule'
  tag stig_id: 'APSC-DV-003260'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24319r493889_fix'
  tag 'documentable'
  tag legacy: ['SV-85021', 'V-70399']
  tag cci: ['CCI-003374']
  tag nist: ['SA-22 b']
end

control 'SV-206610' do
  title 'When updates are applied to the DBMS software, any software components that have been replaced or made unnecessary must be removed.'
  desc "Previous versions of DBMS components that are not removed from the information system after updates have been installed may be exploited by adversaries. 

Some DBMSs' installation tools may remove older versions of software automatically from the information system. In other cases, manual review and removal will be required. In planning installations and upgrades, organizations must include steps (automated, manual, or both) to identify and remove the outdated modules.

A transition period may be necessary when both the old and the new software are required. This should be taken into account in the planning."
  desc 'check', 'If software components that have been replaced or made unnecessary are not removed, this is a finding.'
  desc 'fix', 'Identify and remove software components that have been replaced or made unnecessary.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6870r291498_chk'
  tag severity: 'medium'
  tag gid: 'V-206610'
  tag rid: 'SV-206610r617447_rule'
  tag stig_id: 'SRG-APP-000454-DB-000389'
  tag gtitle: 'SRG-APP-000454'
  tag fix_id: 'F-6870r291499_fix'
  tag 'documentable'
  tag legacy: ['SV-72605', 'V-58175']
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end

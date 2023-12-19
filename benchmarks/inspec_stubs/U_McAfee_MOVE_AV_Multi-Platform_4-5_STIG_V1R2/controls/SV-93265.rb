control 'SV-93265' do
  title 'The McAfee MOVE AV Options Policy must be configured with the location of quarantine to ensure consistency across all systems.'
  desc 'The quarantine on each system represents a potential danger should the files contained within the quarantine be executed inadvertently. 

To centrally manage the quarantine on all systems, the quarantine should always be configured the same across all systems, which will allow management to better control access to those locations.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "Options".

Select each configured Options policy.

Under "Quarantine Manager", verify the Quarantine Directory is set to <SYSTEM_DRIVE>\\Quarantine or another location authorized by the ISSM.

If the Quarantine Directory is not set to <SYSTEM_DRIVE>\\Quarantine, or another location authorized by the ISSM, this is a finding.".'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "Options".

Select each configured Options policy.

Under "Quarantine Manager", configure the Quarantine Directory to <SYSTEM_DRIVE>\\Quarantine, or another location authorized by the ISSM.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78129r2_chk'
  tag severity: 'medium'
  tag gid: 'V-78559'
  tag rid: 'SV-93265r2_rule'
  tag stig_id: 'MV45-OPT-000001'
  tag gtitle: 'MV45-OPT-000001'
  tag fix_id: 'F-85295r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end

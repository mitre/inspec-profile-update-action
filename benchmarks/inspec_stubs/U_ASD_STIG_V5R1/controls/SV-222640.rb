control 'SV-222640' do
  title 'Procedures must be in place to assure the appropriate physical and technical protection of the backup and restoration of the application.'
  desc 'Protection of backup and restoration assets is essential for the successful restore of operations after a catastrophic failure or damage to the system or data files. Failure to follow proper procedures may result in the permanent loss of system data and/or the loss of system capability resulting in failure of the customer’s mission.'
  desc 'check', 'Validate that backup and recovery procedures incorporate protection of the backup and restoration assets.

Verify assets housing the backup data (e.g., SANS, tapes, backup directories, software) and the assets used for restoration (e.g., equipment and system software) are included in the backup and recovery procedures.

If backup and restoration devices are not included in the recovery procedures, this is a finding.'
  desc 'fix', 'Develop and implement procedures to insure that backup and restoration assets are properly protected and stored in an area/location where it is unlikely they would be affected by an event that would affect the primary assets.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24310r493828_chk'
  tag severity: 'medium'
  tag gid: 'V-222640'
  tag rid: 'SV-222640r508029_rule'
  tag stig_id: 'APSC-DV-003090'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24299r493829_fix'
  tag 'documentable'
  tag legacy: ['V-70359', 'SV-84981']
  tag cci: ['CCI-000366', 'CCI-000540']
  tag nist: ['CM-6 b', 'CP-9 (d)']
end

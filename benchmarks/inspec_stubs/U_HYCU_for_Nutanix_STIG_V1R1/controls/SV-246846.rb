control 'SV-246846' do
  title 'The HYCU server must back up audit records at least every seven days onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Regularly backing up audit records to a different system or onto separate media than the system being audited helps to assure, in the event of a catastrophic system failure, the audit records will be retained.'
  desc 'check', %q(Log on to HYCU's Web UI and verify that a backup policy, with "Backup Every" setting set to seven days or less, has been applied to the HYCU Controller VM. 

Navigate to the "Virtual Machines" menu, and in the table list of Virtual Machines, identify the assigned policy in the "Policy" column of the "HYCU VM" row. 

Navigate to the "Policy" menu, left-click the assigned policy, and review "Detailed view".

Verify "Backup Every" setting is set to seven days or less. 

If "Policy" is not assigned to the HYCU Controller VM or assigned policy has "Backup Every" setting set to more than seven days, this is a finding.

Verify HYCU Controller VM backups are successful and are taken every seven days or less. 

Navigate to the "Virtual Machines" menu and left-click "HYCU Controller VM" to reveal all the existing backups (restore points). 

Verify dates between restore points are no longer than seven days.

If the HYCU Controller VM does not have any restore points visible, or if time between restore points is more than seven days, this is a finding.)
  desc 'fix', 'Log on to the HYCU Web UI. Under the "Policies" menu, create a new Policy with "Backup Every" setting set to seven days or less. 

Assign this policy to the HYCU Controller VM from the "Virtual Machines" menu by left-clicking the HYCU controller VM, and then the "Policies" icon (top right), and then selecting the configured policy and left-clicking "Assign".'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50278r768200_chk'
  tag severity: 'medium'
  tag gid: 'V-246846'
  tag rid: 'SV-246846r768202_rule'
  tag stig_id: 'HYCU-AU-000026'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-50232r768201_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-91319' do
  title 'The Samsung Android 7 with Knox must implement the management setting: Enable Audit Log.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify attacks, so that breaches can either be prevented or limited in their scope. They facilitate analysis to improve performance and security. The Requirement Statement lists key events that the system must generate an audit record for.

SFR ID: FAU_GEN.1.1 #8'
  desc 'check', 'Review Samsung Android 7 with Knox configuration settings to determine if the mobile device is configured to enable the Audit Log.

This validation procedure is performed on the MDM Administration Console only.

On the MDM console, do the following:
1. Ask the MDM administrator to display the "Enable Audit Log" checkbox in the "Android Audit Log" rule. 
2. Verify the checkbox is selected.

If the MDM console "Enable Audit Log" is not selected, this is a finding.'
  desc 'fix', 'Configure the Samsung Android 7 with Knox to enable "Audit Log".

On the MDM console, select the "Enable Audit Log" checkbox in the "Android AuditLog" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 7 with Knox 2.x'
  tag check_id: 'C-76293r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76623'
  tag rid: 'SV-91319r1_rule'
  tag stig_id: 'KNOX-07-018800'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-83317r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

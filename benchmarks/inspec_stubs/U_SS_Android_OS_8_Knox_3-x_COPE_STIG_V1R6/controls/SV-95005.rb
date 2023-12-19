control 'SV-95005' do
  title 'Samsung Android 8 with Knox must implement the management setting: Enable Audit Log.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify attacks so that breaches can either be prevented or limited in their scope. They facilitate analysis to improve performance and security. The Requirement Statement lists key events for which the system must generate an audit record.

SFR ID: FAU_GEN.1.1 #8'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is configured to enable the Audit Log.

This validation procedure is performed on the MDM Administration Console only.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Enable Audit Log" check box in the "Android Audit Log" rule. 
2. Verify the check box is selected.

If the MDM console "Enable Audit Log" is not selected, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enable "Audit Log".

On the MDM console, select the "Enable Audit Log" check box in the "Android AuditLog" rule.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79973r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80301'
  tag rid: 'SV-95005r1_rule'
  tag stig_id: 'KNOX-08-004000'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87107r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

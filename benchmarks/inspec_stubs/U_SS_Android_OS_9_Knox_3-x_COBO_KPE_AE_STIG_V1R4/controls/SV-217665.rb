control 'SV-217665' do
  title 'Samsung Android must be configured to enable the Knox audit log.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify attacks so that breaches can be prevented or limited in their scope, and they facilitate analysis to improve performance and security. The requirement statement lists key events for which the system must generate an audit record.

SFR ID: FAU_GEN.1.1 #8'
  desc 'check', 'Review device configuration settings to confirm that the Knox audit log is enabled. 

This procedure is performed on the MDM Administration console only. 

On the MDM console, for the device, in the "Knox audit log" group, verify that "enable audit log" is selected. 

If on the MDM console the "enable audit log" is not selected, this is a finding.'
  desc 'fix', 'Configure Samsung Android to enable the Knox audit log. 

On the MDM console, for the device, in the "Knox audit log" group, select "enable audit log".'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COBO KPE AE'
  tag check_id: 'C-18884r362024_chk'
  tag severity: 'medium'
  tag gid: 'V-217665'
  tag rid: 'SV-217665r388482_rule'
  tag stig_id: 'KNOX-09-000170'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-18882r362025_fix'
  tag 'documentable'
  tag legacy: ['SV-102955', 'V-92867']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

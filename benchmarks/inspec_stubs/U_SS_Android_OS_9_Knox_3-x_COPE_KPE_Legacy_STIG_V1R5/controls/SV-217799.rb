control 'SV-217799' do
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
  ref 'DPMS Target Samsung Android OS 9 Knox 3-x COPE KPE Legacy'
  tag check_id: 'C-19015r362855_chk'
  tag severity: 'medium'
  tag gid: 'V-217799'
  tag rid: 'SV-217799r388482_rule'
  tag stig_id: 'KNOX-09-000175'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-19013r362856_fix'
  tag 'documentable'
  tag legacy: ['SV-103945', 'V-93859']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-102955' do
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
  ref 'DPMS Target SamsungAndroid9withKnox3.x-COBO KPE(AE)'
  tag check_id: 'C-92173r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92867'
  tag rid: 'SV-102955r1_rule'
  tag stig_id: 'KNOX-09-000170'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-99111r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-255188' do
  title 'Microsoft Android 11 must be configured to generate audit records for the following auditable events: Detected integrity violations.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify attacks so that breaches can either be prevented or limited in their scope. They facilitate analysis to improve performance and security. The Requirement Statement lists key events that the system must generate an audit record for.

Application note: Requirement applies only to integrity violation detections that can be logged by the audit logging component.

SFR ID: FMT_SMF_EXT.1.1 #37'
  desc 'check', 'Review Microsoft Android device configuration settings to determine if the mobile device is configured to generate audit records for the following auditable events: Detected integrity violations.

This validation procedure is performed only on the EMM Administration console. 

On the EMM console:
1. Open "Device owner management" section.
2. Verify that "Enable security logging" is toggled to "On".

If the EMM console device policy is not set to enable security logging, this is a finding.'
  desc 'fix', 'Configure the Microsoft Android 11 device to generate audit records for the following auditable events: Detected integrity violations.

On the EMM console:
1. Open "Device owner management" section.
2. Toggle "Enable security logging" to "On".'
  impact 0.5
  ref 'DPMS Target Microsoft Android 11 COBO'
  tag check_id: 'C-58801r870695_chk'
  tag severity: 'medium'
  tag gid: 'V-255188'
  tag rid: 'SV-255188r870696_rule'
  tag stig_id: 'MSFT-11-006100'
  tag gtitle: 'PP-MDF-301420'
  tag fix_id: 'F-58745r869426_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end

control 'SV-258390' do
  title 'Google Android 14 must be configured to generate audit records for the following auditable events: Detected integrity violations.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify attacks so that breaches can be prevented or limited in their scope. They facilitate analysis to improve performance and security. The Requirement Statement lists key events for which the system must generate an audit record.

Note: This requirement applies only to integrity violation detections that can be logged by the audit logging component.

SFR ID: FMT_SMF_EXT.1.1 #37'
  desc 'check', 'Review managed Google Android 14 device configuration settings to determine if the mobile device is configured to generate audit records for the following auditable events: Detected integrity violations.

This validation procedure is performed only on the EMM Administration Console. 

On the EMM console:

COBO and COPE:

1. Open "Device owner management" section.
2. Verify that "Enable security logging" is toggled to "ON".

If the EMM console device policy is not set to enable security logging, this is a finding.'
  desc 'fix', 'Configure the Google Android 14 device to generate audit records for the following auditable events: Detected integrity violations.

On the EMM console:

COBO and COPE:

1. Open "Device owner management" section.
2. Toggle "Enable security logging" to "ON".'
  impact 0.5
  ref 'DPMS Target Google Android 14 COBO'
  tag check_id: 'C-62131r928193_chk'
  tag severity: 'medium'
  tag gid: 'V-258390'
  tag rid: 'SV-258390r928195_rule'
  tag stig_id: 'GOOG-14-007800'
  tag gtitle: 'PP-MDF-333170'
  tag fix_id: 'F-62055r928194_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end

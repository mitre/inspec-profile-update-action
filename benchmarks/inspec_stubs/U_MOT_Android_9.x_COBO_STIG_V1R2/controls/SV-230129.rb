control 'SV-230129' do
  title 'The Motorola Android Pie must be configured to generate audit records for the following auditable events: detected integrity violations.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify attacks so that breaches can either be prevented or limited in their scope. They facilitate analysis to improve performance and security. The Requirement Statement lists key events for which the system must generate an audit record.

Application note: Requirement applies only to integrity violation detections that can be logged by the audit logging component.

SFR ID: FMT_SMF_EXT.1.1 #37'
  desc 'check', 'Review Motorola Android device configuration settings to determine if the mobile device is configured to generate audit records for the following auditable events: detected integrity violations.

This validation procedure is performed only on the MDM Administration Console. 

On the MDM console: 
1. Go to Policy management.
2. Verify "Security Logging" is enabled.

If the MDM console device policy is not set to enable security logging, this is a finding.'
  desc 'fix', 'Configure the Motorola Android device to generate audit records for the following auditable events: detected integrity violations.

On the MDM console: 
1. Go to Policy management.
2. Enable "Security Logging".'
  impact 0.3
  ref 'DPMS Target Motorola Android 9.x COBO STIG'
  tag check_id: 'C-58134r859751_chk'
  tag severity: 'low'
  tag gid: 'V-230129'
  tag rid: 'SV-230129r859753_rule'
  tag stig_id: 'MOTO-09-006100'
  tag gtitle: 'GOOG-09-006100'
  tag fix_id: 'F-58083r859752_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end

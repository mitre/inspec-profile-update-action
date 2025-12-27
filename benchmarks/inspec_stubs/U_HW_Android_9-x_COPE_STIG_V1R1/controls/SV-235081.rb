control 'SV-235081' do
  title 'The Honeywell Mobility Edge Android Pie device must be configured to generate audit records for the following auditable events: detected integrity violations.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify attacks so that breaches can either be prevented or limited in their scope. They facilitate analysis to improve performance and security. The Requirement Statement lists key events the system must generate in an audit record.

Application note: Requirement applies only to integrity violation detections that can be logged by the audit logging component.

SFR ID: FMT_SMF_EXT.1.1 #37'
  desc 'check', 'Review Honeywell Android device configuration settings to determine if the mobile device is configured to generate audit records for the following auditable events: detected integrity violations.

This validation procedure is performed only on the MDM Administration console. 

On the MDM console:
1. Go to Policy management.
2. Confirm Security Logging is enabled.

If the MDM console device policy is not set to enable security logging, this is a finding.'
  desc 'fix', 'Configure the Honeywell Android device to generate audit records for the following auditable events: detected integrity violations.

On the MDM console:
1. Go to Policy management.
2. Enable Security Logging.'
  impact 0.3
  ref 'DPMS Target Honeywell Android 9.x COPE'
  tag check_id: 'C-38300r623258_chk'
  tag severity: 'low'
  tag gid: 'V-235081'
  tag rid: 'SV-235081r626527_rule'
  tag stig_id: 'HONW-09-006100'
  tag gtitle: 'PP-MDF-301420'
  tag fix_id: 'F-38263r623259_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end

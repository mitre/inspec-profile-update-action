control 'SV-108063' do
  title 'Google Android 10 must be configured to generate audit records for the following auditable events: detected integrity violations.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify attacks so that breaches can either be prevented or limited in their scope. They facilitate analysis to improve performance and security. The Requirement Statement lists key events that the system must generate an audit record for.

Application note: Requirement applies only to integrity violation detections that can be logged by the audit logging component.

SFR ID: FMT_SMF_EXT.1.1 #37'
  desc 'check', 'Review Google Android device configuration settings to determine if the mobile device is configured to generate audit records for the following auditable events: detected integrity violations.

This validation procedure is performed only on the MDM Administration Console. 

On the MDM console, do the following:
1. Go to Policy management.
2. Confirm Security Logging is enabled.

If the MDM console device policy is not set to enable security logging, this is a finding.'
  desc 'fix', 'Configure the Google Android device to generate audit records for the following auditable events: detected integrity violations.

On the MDM console, do the following:

On the MDM Console:
1. Go to Policy management.
2. Enable Security Logging.'
  impact 0.3
  ref 'DPMS Target Google Android 10.x'
  tag check_id: 'C-97799r1_chk'
  tag severity: 'low'
  tag gid: 'V-98959'
  tag rid: 'SV-108063r1_rule'
  tag stig_id: 'GOOG-10-006100'
  tag gtitle: 'PP-MDF-301420'
  tag fix_id: 'F-104635r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end

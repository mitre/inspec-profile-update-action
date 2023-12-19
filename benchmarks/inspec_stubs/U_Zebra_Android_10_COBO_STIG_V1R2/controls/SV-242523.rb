control 'SV-242523' do
  title 'Zebra Android 10 must be configured to generate audit records for the following auditable events: detected integrity violations.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. They help identify attacks so that breaches can either be prevented or limited in their scope. They facilitate analysis to improve performance and security. The Rule Title lists key events for which the system must generate an audit record.

Application note: Requirement applies only to integrity violation detections that can be logged by the audit logging component.

SFR ID: FMT_SMF_EXT.1.1 #37'
  desc 'check', 'Review Zebra Android 10 device configuration settings to determine if the mobile device is configured to generate audit records for the following auditable events: detected integrity violations.

This validation procedure is performed only on the MDM Administration Console. 

On the MDM console:
1. Go to Policy management.
2. Confirm Security Logging is enabled.

If the MDM console device policy is not set to enable security logging, this is a finding.'
  desc 'fix', 'Configure the Zebra Android 10 device to generate audit records for the following auditable events: detected integrity violations.

On the MDM console:
1. Go to Policy management.
2. Enable Security Logging.'
  impact 0.3
  ref 'DPMS Target Zebra Android 10 COBO'
  tag check_id: 'C-45798r714412_chk'
  tag severity: 'low'
  tag gid: 'V-242523'
  tag rid: 'SV-242523r714414_rule'
  tag stig_id: 'ZEBR-10-006100'
  tag gtitle: 'PP-MDF-301420'
  tag fix_id: 'F-45755r714413_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end

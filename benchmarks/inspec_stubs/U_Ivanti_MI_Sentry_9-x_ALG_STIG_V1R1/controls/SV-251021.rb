control 'SV-251021' do
  title 'The Sentry must send an alert to, at a minimum, the ISSO and SCA when an audit processing failure occurs.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Possible audit processing failures also include the inability of Sentry to write to the central audit log.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations, (i.e., all audit data storage repositories combined), or both.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the Sentry sends an alert to, at a minimum, the ISSO and SCA when an audit processing failure occurs.

1. Log in to MobileIron Sentry.
2. Go to Monitoring >> Alert Configuration.
3. Verify "Send Notifications" is enabled.
4. Verify an email list containing the ISSM and SCA is input in the Email List.
5. Verify "Alert Notification Management" section is set to meet organizational requirements.

If the "Alert Notification Management" section is not set to meet organizational requirements, this is a finding.'
  desc 'fix', 'Configure the Sentry to send an alert to, at a minimum, the ISSO and SCA when an audit processing failure occurs.

1. Log in to MobileIron Sentry.
2. Go to Monitoring >> Alert Configuration.
3. Configure "Send Notifications" to enabled.
4. Configure an email list containing the ISSM and SCA in the Email List.
5. Configure "Alert Notification Management" section is set to meet organizational requirements.

Refer to the MobileIron Sentry 9.8.0 Guide "Configuring Sentry alert notifications" section for more information.'
  impact 0.3
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54456r802283_chk'
  tag severity: 'low'
  tag gid: 'V-251021'
  tag rid: 'SV-251021r802285_rule'
  tag stig_id: 'MOIS-AL-000260'
  tag gtitle: 'SRG-NET-000088-ALG-000054'
  tag fix_id: 'F-54410r802284_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end

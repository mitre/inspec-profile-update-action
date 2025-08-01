control 'SV-250998' do
  title 'MobileIron Sentry must generate an immediate real-time alert of all audit failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.'
  desc 'check', 'Verify the MobileIron Sentry is configured to send alerts for failure events in MobileIron Sentry System Manager web GUI. 

1. Log in to MobileIron Sentry.
2. Go to Monitoring >> Alert Configuration.
3. Verify Alert monitoring is configured.

If Alert Configuration settings are not configured, this is a finding. 

Refer to the "Alert Configuration" section of the "MobileIron Sentry 9.8.0 Guide for MobileIron Core" for more information.'
  desc 'fix', 'Configure the MobileIron Sentry to send alerts for failure events in MobileIron Sentry System Manager web GUI. 

1. Log in to MobileIron Sentry.
2. Go to Monitoring >> Alert Configuration.
3. Check "Send Notification".
4. Apply Email List.
5. Enter Alerts Per Hour.
6. Enter Batch Time Interval (min).
7. Select "Default Alert Action".
8. Apply.
9. Add Alert Notification Management.
10. Add Alert ID.
11. Add "Action" from dropdown.
12. Click "Apply" and "Save" in the top right corner.

Refer to the "Alert Configuration" section of the "MobileIron Sentry 9.8.0 Guide for MobileIron Core" for more information.'
  impact 0.3
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54433r802214_chk'
  tag severity: 'low'
  tag gid: 'V-250998'
  tag rid: 'SV-250998r802216_rule'
  tag stig_id: 'MOIS-ND-000690'
  tag gtitle: 'SRG-APP-000360-NDM-000295'
  tag fix_id: 'F-54387r802215_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end

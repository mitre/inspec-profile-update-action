control 'SV-251039' do
  title 'The Sentry must offload audit records onto a centralized log server in real time.'
  desc 'Offloading ensures audit information does not get overwritten if the limited audit storage capacity is reached and also protects the audit record in case the system/component being audited is compromised.

Offloading is a common process in information systems with limited audit storage capacity. The audit storage on the ALG is used only in a transitory fashion until the system can communicate with the centralized log server designated for storing the audit records, at which point the information is transferred. However, DoD requires that the log be transferred in real time which indicates that the time from event detection to offloading is seconds or less.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the Sentry produces audit records onto a centralized log server in real time.

1. Log in to MobileIron Sentry.
2. Go to Settings >> Syslog.
3. Verify a syslog server is configured. If it is not configured, this is a finding.
4. Click on the syslog server(s) and in the "Modify Syslog" pop-up dialog, under the "Facility Type", verify the checkbox for "Audit" is selected. If it is not selected, this is a finding.

For more information, go to the "MobileIron Sentry 9.8.0 Guide for Core" and refer to the main section "Standalone Sentry Settings", which includes a subsection detailing the log representation format in "Audit log representation and format".

The audit logs contain additional information on the type of events that occurred. Also included is date and timestamp, the source of the event, the location of the event, and the result of the action whether a success/failure.'
  desc 'fix', '1. Log in to MobileIron Sentry.
2. Go to Settings >> Syslog.
3. Configure a new Syslog Server if not already added.
4. Click on the syslog server(s) and in the "Modify Syslog"/"Add Syslog" pop-up dialog, under the "Facility Type", click the checkbox for "Audit". 
5. Set the Admin State to "Enable".
6. Click "Apply".'
  impact 0.3
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54474r802337_chk'
  tag severity: 'low'
  tag gid: 'V-251039'
  tag rid: 'SV-251039r802339_rule'
  tag stig_id: 'MOIS-AL-001370'
  tag gtitle: 'SRG-NET-000511-ALG-000051'
  tag fix_id: 'F-54428r802338_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

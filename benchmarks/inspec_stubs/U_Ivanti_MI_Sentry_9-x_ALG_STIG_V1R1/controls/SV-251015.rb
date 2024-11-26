control 'SV-251015' do
  title 'The Sentry must produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the gateway logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the Sentry produces audit records containing information to establish what type of events occurred.

1. Log in to MobileIron Sentry.
2. Go to Settings >> Syslog.
3. Verify a syslog server is configured.
4. Click on the syslog server(s) and in the "Modify Syslog" pop-up dialog, under the "Facility Type", verify the checkbox for "Audit" is selected.

If the syslog server is not configured or "Audit" is not selected under "Modify Syslog", this is a finding.

For more information, go to the "MobileIron Sentry 9.8.0 Guide for Core" and refer to the section "Standalone Sentry Settings", which includes a subsection detailing the log representation format in "Audit log representation and format".

The audit logs contain additional information on the type of events that occurred. Also included is date and timestamp, the source of the event, the location of the event, and the result of the action whether a success or failure.'
  desc 'fix', 'Configure the Sentry to produce audit records containing information to establish what type of events occurred.

1. Log in to MobileIron Sentry.
2. Go to Settings >> Syslog.
3. Configure a new Syslog Server if not already added.
4. Click on the syslog server(s) and in the "Modify Syslog"/"Add Syslog" pop-up dialog, under the "Facility Type", click the checkbox for "Audit". 
5. Set the Admin State to "Enable".
6. Click "Apply".'
  impact 0.3
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54450r802265_chk'
  tag severity: 'low'
  tag gid: 'V-251015'
  tag rid: 'SV-251015r802267_rule'
  tag stig_id: 'MOIS-AL-000200'
  tag gtitle: 'SRG-NET-000074-ALG-000043'
  tag fix_id: 'F-54404r802266_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end

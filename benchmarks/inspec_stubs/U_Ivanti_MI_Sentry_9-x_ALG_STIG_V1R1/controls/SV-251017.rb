control 'SV-251017' do
  title 'The Sentry must produce audit records containing information to establish where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know where events occurred, such as network element components, modules, device identifiers, node names, and functionality.

Associating information about where the event occurred within the network provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the Sentry produces audit records containing information to establish where the events occurred.

1. Log in to MobileIron Sentry.
2. Go to Settings >> Syslog.
3. Verify a syslog server is configured.
4. Click on the syslog server(s) and in the "Modify Syslog" pop-up dialog, under the "Facility Type", verify the checkbox for "Audit" is selected.

If the syslog server is not configured or "Audit" is not selected under "Modify Syslog", this is a finding. 

For more information, go to the "MobileIron Sentry 9.8.0 Guide for Core" and refer to the main section "Standalone Sentry Settings", which includes a subsection detailing the log representation format in "Audit log representation and format".

The audit logs contain additional information on the type of events that occurred. Also included is the date and timestamp, the source of the event, the location of the event, the result of the action whether a success or failure.'
  desc 'fix', 'Configure the Sentry to produce audit records containing information to establish where the events occurred.

1. Log in to MobileIron Sentry.
2. Go to Settings >> Syslog.
3. Configure a new Syslog Server if not already added.
4. Click on the syslog server(s) and in the "Modify Syslog"/"Add Syslog" pop-up dialog, under the "Facility Type", click the checkbox for "Audit" .
5. Set the Admin State to "Enable".
6. Click "Apply".'
  impact 0.3
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54452r802271_chk'
  tag severity: 'low'
  tag gid: 'V-251017'
  tag rid: 'SV-251017r802273_rule'
  tag stig_id: 'MOIS-AL-000220'
  tag gtitle: 'SRG-NET-000076-ALG-000045'
  tag fix_id: 'F-54406r802272_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end

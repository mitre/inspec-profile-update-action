control 'SV-251019' do
  title 'The Sentry must produce audit records containing information to establish the outcome of the events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the network.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the network after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.

This requirement does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the Sentry produces audit records containing information to establish the outcome of the events.

1. Log in to MobileIron Sentry.
2. Go to Settings >> Syslog.
3. Verify a syslog server is configured.
4. Click on the syslog server(s) and in the "Modify Syslog" pop-up dialog, under the "Facility Type", verify the checkbox for "Audit" is selected.

If the syslog server is not configured or if "Audit" is not selected under "Modify Syslog", this is a finding. 

For more information, go to the "MobileIron Sentry 9.8.0 Guide for Core" and refer the following main section "Standalone Sentry Settings" under which there is a sub-section detailing the log representation format in "Audit log representation and format".

The audit logs contain additional information on the type of events that occurred. Also included is the date and timestamp, the source of the event, the location of the event, and the result of the action whether a success/failure.'
  desc 'fix', 'Configure the Sentry to produce audit records containing information to establish the outcome of the events.

1. Log in to MobileIron Sentry.
2. Go to Settings >> Syslog.
3. Configure a new Syslog Server if not already added.
4. Click on the syslog server(s) and in the "Modify Syslog"/"Add Syslog" pop-up dialog, under the "Facility Type", click the checkbox for "Audit". 
5. Set the Admin State to "Enable".
6. Click "Apply".'
  impact 0.3
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54454r802277_chk'
  tag severity: 'low'
  tag gid: 'V-251019'
  tag rid: 'SV-251019r802279_rule'
  tag stig_id: 'MOIS-AL-000240'
  tag gtitle: 'SRG-NET-000078-ALG-000047'
  tag fix_id: 'F-54408r802278_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end

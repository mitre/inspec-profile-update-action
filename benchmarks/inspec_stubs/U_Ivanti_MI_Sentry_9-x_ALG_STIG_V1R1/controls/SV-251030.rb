control 'SV-251030' do
  title 'The Sentry must offload audit records onto a centralized log server.'
  desc 'Without the capability to select a user session to capture or view, investigations into suspicious or harmful events would be hampered by the volume of information captured.

The intent of this requirement is to ensure the capability to select specific sessions to capture is available in order to support general auditing/incident investigation, or to validate suspected misuse by a specific user. Examples of session events that may be captured include, port mirroring, tracking websites visited, and recording information and/or file transfers.'
  desc 'check', 'Verify Sentry offloads audit records onto a centralized log server.

1. Log in to MobileIron Sentry.
2. Go to Settings >> Syslog.
3. Verify a syslog server is configured. If it is not configured, this is a finding.
4. Click on the syslog server(s) and in the "Modify Syslog" pop-up dialog, under the "Facility Type", verify the checkbox for "Audit" is selected.

If Sentry is not configured to offload audit records, this is a finding.

For more information, go to the "MobileIron Sentry 9.8.0 Guide for Core" and refer to the main section "Standalone Sentry Settings", which includes a subsection detailing the log representation format in "Audit log representation and format".

The audit logs contain additional information on the type of events that occurred. Also included is date and timestamp, the source of the event, the location of the event, and the result of the action whether success/failure.'
  desc 'fix', 'Configure the ALG to offload audit records onto a centralized log server.

1. Log in to MobileIron Sentry.
2. Go to Settings >> Syslog.
3. Click on the syslog server(s) and in the "Modify Syslog" pop-up dialog, under the "Facility Type", click the checkbox for "Audit".

For more information, go to the "MobileIron Sentry 9.8.0 Guide for Core" and refer to the main section "Standalone Sentry Settings", which includes a subsection detailing the log representation format in "Audit log representation and format".

The audit logs contain additional information on the type of events that occurred. Also included is date and timestamp, the source of the event, the location of the event, and the result of the action whether a success/failure.'
  impact 0.3
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54465r802310_chk'
  tag severity: 'low'
  tag gid: 'V-251030'
  tag rid: 'SV-251030r802312_rule'
  tag stig_id: 'MOIS-AL-000870'
  tag gtitle: 'SRG-NET-000334-ALG-000050'
  tag fix_id: 'F-54419r802311_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

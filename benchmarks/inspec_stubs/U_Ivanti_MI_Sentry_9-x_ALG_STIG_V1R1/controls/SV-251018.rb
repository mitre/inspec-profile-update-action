control 'SV-251018' do
  title 'The Sentry must produce audit records containing information to establish the source of the events.'
  desc 'Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.'
  desc 'check', 'Verify the Sentry produces audit records containing information to establish the source of the events.

1. Log in to MobileIron Sentry.
2. Go to Settings >> Syslog.
3. Verify a syslog server is configured.
4. Click on the syslog server(s) and in the "Modify Syslog" pop-up dialog, under the "Facility Type", verify the checkbox for "Audit" is selected.

If the syslog server is not configured or "Audit" is not selected under "Modify Syslog", this is a finding. 

For more information, go to the "MobileIron Sentry 9.8.0 Guide for Core" and refer to the main section "Standalone Sentry Settings", which includes a subsection detailing the log representation format in "Audit log representation and format".

The audit logs contain additional information on the type of events that occurred. Also included is date and timestamp, the source of the event, the location of the event, and the result of the action whether a success or failure.'
  desc 'fix', 'Configure the Sentry to produce audit records containing information to establish the source of the events.

1. Log in to MobileIron Sentry.
2. Go to Settings >> Syslog.
3. Configure a new Syslog Server if not already added.
4. Click on the syslog server(s) and in the "Modify Syslog"/"Add Syslog" pop-up dialog, under the "Facility Type", click the checkbox for "Audit".
5. Set the Admin State to "Enable".
6. Click "Apply".'
  impact 0.3
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54453r802274_chk'
  tag severity: 'low'
  tag gid: 'V-251018'
  tag rid: 'SV-251018r802276_rule'
  tag stig_id: 'MOIS-AL-000230'
  tag gtitle: 'SRG-NET-000077-ALG-000046'
  tag fix_id: 'F-54407r802275_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end

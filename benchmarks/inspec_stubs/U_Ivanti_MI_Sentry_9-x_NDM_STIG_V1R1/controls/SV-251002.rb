control 'SV-251002' do
  title 'MobileIron Sentry must off-load audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify MobileIron Sentry is configured to offload audit records to a different system. 

1. Log in to MobileIron Sentry.
2. Go to Settings >> Syslog.
3. Verify that a syslog server is configured.
 
If the syslog server is not configured, this is a finding.'
  desc 'fix', 'Configure MobileIron Sentry to forward/offload audit to a different system.

1. Log in to MobileIron Sentry.
2. Go to Settings >> Syslog.
3. Configure a new syslog server if not already added.
4. Click on the syslog server(s) and in the "Modify Syslog"/"Add Syslog" pop-up dialog, under the "Facility Type", click the checkbox for "Audit". 
5. Set the Admin State to "Enable".
6. Click "Apply".'
  impact 0.3
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54437r802226_chk'
  tag severity: 'low'
  tag gid: 'V-251002'
  tag rid: 'SV-251002r802228_rule'
  tag stig_id: 'MOIS-ND-000900'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-54391r802227_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

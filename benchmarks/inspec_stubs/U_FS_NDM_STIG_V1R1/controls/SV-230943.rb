control 'SV-230943' do
  title 'The Forescout must configure a remote syslog where audit records are stored on a centralized logging target that is different from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', %q(Verify the syslog.

1. Log on to Forescout Administrator UI with admin or operator credentials.
2. From the menu, select Tools >> Options >> Modules >> Syslog >> Send Events To.
3. Click the IP address of the site's centralized syslog  server.
4. Verify "Use TLS" is checked.
5. Verify OCSP, Identity, Facility, and Severity, as required by the SSP, are configured.

If the site's syslog server is not configured or if it is not configure to use TLS and OCSP, this is a finding.)
  desc 'fix', %q(Configure the syslog.

1. Log on to Forescout Administrator UI with admin or operator credentials.
2. From the menu, select Tools >> Options >> Modules >> Syslog >> Send Events To.
3. Click "Add".
4. Enter the IP address of the site's centralized syslog.
5. Check "Use TLS".
6. Configure OCSP, Identity, Facility, and Severity as required by the SSP.)
  impact 0.3
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33873r615872_chk'
  tag severity: 'low'
  tag gid: 'V-230943'
  tag rid: 'SV-230943r615886_rule'
  tag stig_id: 'FORE-NM-000150'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-33846r603669_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

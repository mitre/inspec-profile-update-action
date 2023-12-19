control 'SV-233323' do
  title 'Forescout must be configured to log records onto a centralized events server. This is required for compliance with C2C Step 1.'
  desc 'Keeping an established, connection-oriented audit record is essential to keeping audit logs in accordance with DoD requirements.'
  desc 'check', "If DoD is not at C2C Step 1 or higher, this is not a finding.

1. Go to Tools >> Options >> Syslog.
2. Verify a central log server's IP address is configured.

If Forescout does not configured to log records onto a centralized events server, this is a finding."
  desc 'fix', 'Configure Syslog server with TCP, as well as configure Syslog to alert if the communication between the Syslog server and the Forescout appliance loses connectivity.

1. Go to Tools >> Options >> Syslog.
2. Click Add/Edit.
3. Configure the Syslog:
- Syslog Server IP address
- Server Port
- Server Protocol set to TCP
- Check the Use TLS setting
- Configure the Identity, Facility, and Severity.
4. Click "Ok".
5. Click "Apply".

Note: A secondary syslog server is required to fully meet this requirement (covered in NDM STIG). Use the same instructions to configure a second syslog.'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36518r811394_chk'
  tag severity: 'medium'
  tag gid: 'V-233323'
  tag rid: 'SV-233323r856509_rule'
  tag stig_id: 'FORE-NC-000150'
  tag gtitle: 'SRG-NET-000333-NAC-001340'
  tag fix_id: 'F-36483r605673_fix'
  tag 'documentable'
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']
end

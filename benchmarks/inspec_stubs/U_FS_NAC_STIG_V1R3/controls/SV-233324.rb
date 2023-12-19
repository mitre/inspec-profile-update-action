control 'SV-233324' do
  title 'Forescout must off-load log records onto a different system. This is required for compliance with C2C Step 1.'
  desc 'Having a separate, secure location for log records is essential to the preservation of logs as required by policy.'
  desc 'check', "If DoD is not at C2C Step 1 or higher, this is not a finding.

1. Go to Tools >> Options >> Syslog.
2. Verify a syslog server's IP address is configured.

If each Forescout device does not offload log records to a separate device, this is a finding."
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
5. Click "Apply".'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36519r811396_chk'
  tag severity: 'medium'
  tag gid: 'V-233324'
  tag rid: 'SV-233324r811397_rule'
  tag stig_id: 'FORE-NC-000160'
  tag gtitle: 'SRG-NET-000334-NAC-001350'
  tag fix_id: 'F-36484r605676_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

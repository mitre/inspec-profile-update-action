control 'SV-104211' do
  title 'Symantec ProxySG must use a centralized log server.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Determine whether audit log off-loading is configured.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Access Logging >> Logs.
3. Click "Upload Client" and Verify that a "Client type" is specified. All client types use TCP for communication to the target server (FTP/S, HTTP/S, Kafka, etc.).

If Symantec ProxySG does not use a centralized log server, this is a finding.'
  desc 'fix', %q(Configure audit log off-loading.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Access Logging >> Logs.
3. Configure the "Upload Client" and "Upload Schedule" capabilities. (All client types use TCP for communication to the site's event server.))
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93443r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94257'
  tag rid: 'SV-104211r1_rule'
  tag stig_id: 'SYMP-AG-000210'
  tag gtitle: 'SRG-NET-000334-ALG-000050'
  tag fix_id: 'F-100373r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

control 'SV-258586' do
  title 'The ICS must be configured to use TLS 1.2, at a minimum.'
  desc 'Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

NIST SP 800-52 Rev2 provides guidance for client negotiation on either DOD-only or public-facing servers.

'
  desc 'check', 'Determine if the ICS uses TLS 1.2 to protect remote access transmissions.

In the ICS Web UI, navigate to System >> Configuration >> Inbound SSL Options.
1. Under Allowed SSL and TLS Version, verify "Accept only TLS 1.2 (maximize security)" is checked.
2. Navigate to System >> Configuration >> Outbound SSL Options.
3. Under Allowed SSL and TLS Version, verify "Accept only TLS 1.2 (maximize security)" is checked.

If the ICS does not use TLS 1.2, at a minimum, this is a finding.'
  desc 'fix', 'Configure the ICS to uses TLS 1.2 to protect remote access transmissions.

In the ICS Web UI, navigate to System >> Configuration >> Inbound SSL Options.
1. Under Allowed SSL and TLS Version, check the box for "Accept only TLS 1.2 (maximize security)".
2. Click "Save Changes".
3. Click "Proceed" for acceptance of Cipher Change.

Navigate to System >> Configuration >> Outbound SSL Options.
1. Under Allowed SSL and TLS Version, check the box for "Accept only TLS 1.2 (maximize security)".
2. Click "Save Changes".
3. Click "Proceed" for acceptance of Cipher Change.'
  impact 0.7
  ref 'DPMS Target Ivanti Connect Secure VPN'
  tag check_id: 'C-62326r930444_chk'
  tag severity: 'high'
  tag gid: 'V-258586'
  tag rid: 'SV-258586r930446_rule'
  tag stig_id: 'IVCS-VN-000060'
  tag gtitle: 'SRG-NET-000062-VPN-000200'
  tag fix_id: 'F-62235r930445_fix'
  tag satisfies: ['SRG-NET-000062-VPN-000200', 'SRG-NET-000371-VPN-001650', 'SRG-NET-000530-VPN-002340', 'SRG-NET-000540-VPN-002350']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-001453', 'CCI-002418']
  tag nist: ['AC-17 (2)', 'AC-17 (2)', 'SC-8']
end

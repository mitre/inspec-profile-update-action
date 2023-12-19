control 'SV-233332' do
  title 'Forescout must use TLS 1.2, at a minimum, to protect the confidentiality of information passed between the endpoint agent and Forescout for the purposes of client posture assessment. This is required for compliance with C2C Step 1.'
  desc 'Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.'
  desc 'check', 'If DoD is not at C2C Step 1 or higher, this is not a finding.

Verify Forescout is configured to a list of DoD-approved certificate types and CAs.

Verify the TLS session is configured to automatically terminate any session if the client does not have a suitable certificate.

For TLS connections, if Forescout is not configured to use TLS 1.2 at a minimum, this is a finding.'
  desc 'fix', %q(Configure the SecureConnector to ensure the minimum supported TLS version is set to TLS 1.2.

Log on to the Forescout UI.

1. Select Tools >> Options >> Certificates.
2. Check the Ongoing TLS Sessions section, view the Re-verify TLS Sessions.
3. Change the Re-verify TLS Sessions to Every 1 Day or in accordance with the site's SSP, then click "Apply".
4. Next, select the HPS Inspection Engine >> SecureConnector.
5. In the Client-Server Connection, ensure the Minimum Supported TLS Version is set to TLS version 1.2.)
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36527r811413_chk'
  tag severity: 'medium'
  tag gid: 'V-233332'
  tag rid: 'SV-233332r811414_rule'
  tag stig_id: 'FORE-NC-000270'
  tag gtitle: 'SRG-NET-000062-NAC-000340'
  tag fix_id: 'F-36492r803481_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

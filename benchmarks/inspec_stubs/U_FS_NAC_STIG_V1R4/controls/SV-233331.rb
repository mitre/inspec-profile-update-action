control 'SV-233331' do
  title 'For TLS connections, Forescout must automatically terminate the session when a client certificate is requested and the client does not have a suitable certificate. This is required for compliance with C2C Step 1.'
  desc 'In accordance with NIST SP 800-52, the TLS server must terminate the connection with a fatal “handshake failure” alert when a client certificate is requested and the client does not have a suitable certificate.

During the TLS handshake negotiation, a "client certificate request" that includes a list of the types of certificates supported and the Distinguished Names of acceptable Certification Authorities (CAs) is sent to the client.

TLS handshake enables the SSL or TLS client and server to establish the secret keys with which they communicate.'
  desc 'check', 'If DoD is not at C2C Step 1 or higher, this is not a finding.

Verify Forescout is configured to a list of DoD-approved certificate types and CAs.

Verify the TLS session is configured to automatically terminate any session if the client does not have a suitable certificate.

For TLS connections, if Forescout is not configured to automatically terminate the session when the client does not have a suitable certificate, this is a finding.'
  desc 'fix', %q(Use the Forescout Administrator UI to configure the certificate options to require the Re-verify TLS Sessions is set to every 1 day, or in accordance with the SSP.

1. Log on to the Forescout UI.
2. Select Tools >> Options >> Certificates.
3. Check that in the Ongoing TLS Sessions section, view the Re-verify TLS Sessions.
4. Change the Re-verify TLS Sessions to Every 1 Day or in accordance with the site's SSP, then click "Apply".
5. Next, select the HPS Inspection Engine >> SecureConnector.
6. In the Client-Server Connection, ensure the Minimum Supported TLS Version is set to TLS version 1.2.)
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36526r811411_chk'
  tag severity: 'medium'
  tag gid: 'V-233331'
  tag rid: 'SV-233331r856515_rule'
  tag stig_id: 'FORE-NC-000260'
  tag gtitle: 'SRG-NET-000517-NAC-002370'
  tag fix_id: 'F-36491r803479_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end

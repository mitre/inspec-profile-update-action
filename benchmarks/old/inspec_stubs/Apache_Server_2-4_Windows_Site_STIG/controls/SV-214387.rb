control 'SV-214387' do
  title 'The Apache web server must set an inactive timeout for completing the TLS handshake.'
  desc "Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. 

Timeouts for completing the TLS handshake, receiving the request headers and/or the request body from the client. If the client fails to complete each of these stages within the configured time, a 408 REQUEST TIME OUT error is sent.

For SSL virtual hosts, the handshake timeout values is the time needed to do the initial SSL handshake. If the user's browser is configured to query certificate revocation lists and the CRL server is not reachable, the initial SSL handshake may take a significant time until the browser gives up waiting for the CRL. Therefore the handshake timeout should take this possible overhead into consideration for SSL virtual hosts (if necessary). The body timeout values include the time needed for SSL renegotiation (if necessary)."
  desc 'check', %q(Review the <'INSTALLED PATH'>\conf\httpd.conf file.

Verify the "mod_reqtimeout" is loaded.

If it does not exist, this is a finding.

If the "mod_reqtimeout" module is loaded but the "RequestReadTimeout" directive is not configured, this is a finding.

Note: The "RequestReadTimeout" directive must be explicitly configured (i.e., not left to a default value) to a value compatble with the organization's operations.)
  desc 'fix', %q(Edit the <'INSTALLED PATH'>\conf\httpd.conf file and load the "mod_reqtimeout" module.

Set the "RequestReadTimeout" directive.

The "RequestReadTimeout" directive must be explicitly configured (i.e., not left to a default value) to a value compatible with the organization's operations.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Site'
  tag check_id: 'C-15598r505107_chk'
  tag severity: 'medium'
  tag gid: 'V-214387'
  tag rid: 'SV-214387r505109_rule'
  tag stig_id: 'AS24-W2-000650'
  tag gtitle: 'SRG-APP-000295-WSR-000134'
  tag fix_id: 'F-15596r505108_fix'
  tag 'documentable'
  tag legacy: ['SV-102649', 'V-92561']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end

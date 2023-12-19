control 'SV-254947' do
  title 'The Tanium Server certificate must be signed by a DOD Certificate Authority.'
  desc 'The Tanium Server has the option to use a "self-signed" certificate or a Trusted Certificate Authority signed certificate for SSL connections. During evaluations of Tanium in Lab settings, customers often conclude that a "self-signed" certificate is an acceptable risk. However, in production environments it is critical that a SSL certificate signed by a Trusted Certificate Authority be used on the Tanium Server in lieu of an untrusted and insecure "self-signed" certificate.'
  desc 'check', "1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. When connected, review the Certificate for the Tanium Server.

3. In the web browser, view the presented Certificate and verify that the Certificate shows as issued by a DOD Root CA. Also verify that the Certification path's top-level is a DOD Root CA.

4. If the certificate authority is not DOD Root CA, this is a finding."
  desc 'fix', 'Request or regenerate the certificate from a DOD Root Certificate Authority.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58560r867739_chk'
  tag severity: 'medium'
  tag gid: 'V-254947'
  tag rid: 'SV-254947r867741_rule'
  tag stig_id: 'TANS-AP-001130'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-58504r867740_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end

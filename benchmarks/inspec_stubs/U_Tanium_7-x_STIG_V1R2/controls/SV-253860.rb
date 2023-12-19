control 'SV-253860' do
  title 'The Tanium Server certificate must be signed by a DoD certificate authority (CA).'
  desc 'The Tanium Server has the option to use a "self-signed" certificate or a trusted CA signed certificate for SSL connections. During evaluations of Tanium in lab settings, customers often conclude that a "self-signed" certificate is an acceptable risk. However, in production environments it is critical that an SSL certificate signed by a trusted CA be used on the Tanium Server in lieu of an untrusted and insecure "self-signed" certificate.'
  desc 'check', "1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.

2. When connected, review the certificate for the Tanium Server as noted below.

3. In the web browser, view the certificate and verify it was issued by a DoD root CA. Also verify the certification path's top level is a DoD root CA.

If the certificate authority is not DoD Root CA, this is a finding."
  desc 'fix', 'Request or regenerate the certificate from a DoD root CA.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57312r842606_chk'
  tag severity: 'medium'
  tag gid: 'V-253860'
  tag rid: 'SV-253860r850257_rule'
  tag stig_id: 'TANS-SV-000036'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-57263r842607_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end

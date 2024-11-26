control 'SV-81603' do
  title 'The Tanium Server certificate must be signed by a DoD Certificate Authority.'
  desc 'The Tanium Server has the option to use a "self-signed" certificate or a Trusted Certificate Authority signed certificate for SSL connections. During evaluations of Tanium in Lab settings, customers often conclude that a "self-signed" certificate is an acceptable risk. However, in production environments it is critical that a SSL certificate signed by a Trusted Certificate Authority be used on the Tanium Server in lieu of an untrusted and insecure "self-signed" certificate.'
  desc 'check', 'Access the Tanium Server console via a web browser.

When connected, review the Certificate for the Tanium Server. (In Internet Explorer, right-click on the page, select “Properties”, click on the “Certificates” tab.)

On the “General” tab, validate the Certificate shows as issued by DOD CA-##.

On Certification “Path” tab, validate the path top-level is DoD Root CA 2.

If the certificate authority is not DoD Root, this is a finding.'
  desc 'fix', 'Request or regenerate the certificate from a DoD Certificate Authority.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67749r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67113'
  tag rid: 'SV-81603r1_rule'
  tag stig_id: 'TANS-SV-000036'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-73213r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end

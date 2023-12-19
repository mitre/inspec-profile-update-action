control 'SV-207533' do
  title 'A BIND 9.x server implementation must be operating on a Current-Stable version as defined by ISC.'
  desc 'The BIND STIG was written to incorporate capabilities and features provided in BIND version 9.9.x. However, it is recognized that security vulnerabilities in BIND are identified and then addressed on a regular, ongoing basis. Therefore it is required that the product be maintained at the latest stable versions in order to address vulnerabilities that are subsequently identified and can then be remediated via updates to the product.

Failure to run a version of BIND that has the capability to implement all of the required security features and that does provide services compliant to the DNS RFCs can have a severe impact on the security posture of a DNS infrastructure. Without the required security in place, a DNS implementation is vulnerable to many types of attacks and could be used as a launching point for further attacks on the organizational network that is utilizing the DNS implementation.

'
  desc 'check', 'Verify that the BIND 9.x server is at a version that is considered "Current-Stable" by ISC or latest supported version of BIND when BIND is installed as part of a specific vendor implementation where the vendor maintains the BIND patches.

# named -v

The above command should produce a version number similar to the following:

BIND 9.9.4-RedHat-9.9.4-29.el7_2.3

If the server is running a version that is not listed as "Current-Stable" by ISC, this is a finding.'
  desc 'fix', 'Update the BIND 9.x server to a version that is listed as “Current-Stable” by ISC or latest supported version of BIND when BIND is installed as part of a specific vendor implementation where the vendor maintains the BIND patches.'
  impact 0.7
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7788r283653_chk'
  tag severity: 'high'
  tag gid: 'V-207533'
  tag rid: 'SV-207533r612253_rule'
  tag stig_id: 'BIND-9X-001000'
  tag gtitle: 'SRG-APP-000516-DNS-000097'
  tag fix_id: 'F-7788r283654_fix'
  tag satisfies: ['SRG-APP-000516-DNS-000097', 'SRG-APP-000516-DNS-000103']
  tag 'documentable'
  tag legacy: ['SV-86989', 'V-72365']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

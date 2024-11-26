control 'SV-88757' do
  title 'The Cisco IOS XE router must obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', "Review the router configuration to determine if a CA trust point has been configured. The CA trust point will contain the URL of the CA in which the router has enrolled with.

Verify this is a DoD or DoD-approved CA. This will ensure the router has enrolled and received a certificate from a trusted CA.

A remote end-point's certificate will always be validated by the router by verifying the signature of the CA on the certificate using the CA's public key, which is contained in the router's certificate it received at enrollment.

The CA trust point configuration would look similar to the following example:

crypto pki trustpoint APPROVED_CA
enrollment url http://xxx.example.com

If the router is not configured to obtain its public key certificates from an approved service provider, this is a finding."
  desc 'fix', 'Configure the router configuration to use CA trust point that is a DoD or DoD-approved CA.

The CA trust point configuration would look similar to the following example:

crypto pki trustpoint APPROVED_CA
enrollment url http://xxx.example.com'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74175r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74083'
  tag rid: 'SV-88757r2_rule'
  tag stig_id: 'CISR-ND-000141'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-80623r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end

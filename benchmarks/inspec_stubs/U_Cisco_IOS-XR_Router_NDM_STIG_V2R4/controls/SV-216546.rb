control 'SV-216546' do
  title 'The Cisco router must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority (CA) at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', "Review the router configuration to determine if a CA trust point has been configured. The CA trust point will contain the URL of the CA in which the router has enrolled with. Verify this is a DoD or DoD-approved CA. This will ensure the router has enrolled and received a certificate from a trusted CA. The CA trust point configuration would look similar to the example below.

crypto pki trustpoint CA_X
 enrollment url http://trustpoint1.example.com

Note: A remote end-point's certificate will always be validated by the router by verifying the signature of the CA on the certificate using the CA's public key, which is contained in the router's certificate it received at enrollment.

Note: This requirement is not applicable if the router does not have any public key certificates.

If the Cisco router is not configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider, this is a finding."
  desc 'fix', 'Configure the router to obtain its public key certificates from an appropriate certificate policy through an approved service provider as show in the example below.

RP/0/0/CPU0:R3(config)#crypto ca trustpoint CA_X
RP/0/0/CPU0:R3(config-trustp)#enrollment url http://trustpoint1.example.com'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17781r288324_chk'
  tag severity: 'medium'
  tag gid: 'V-216546'
  tag rid: 'SV-216546r879887_rule'
  tag stig_id: 'CISC-ND-001440'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-17778r288325_fix'
  tag 'documentable'
  tag legacy: ['SV-105633', 'V-96495']
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end

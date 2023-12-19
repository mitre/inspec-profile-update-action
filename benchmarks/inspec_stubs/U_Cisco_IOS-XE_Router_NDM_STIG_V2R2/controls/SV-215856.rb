control 'SV-215856' do
  title 'The Cisco router must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority (CA) at medium assurance or higher, this CA will suffice.'
  desc 'check', "Review the router configuration to determine if a CA trust point has been configured. The CA trust point will contain the URL of the CA in which the router has enrolled with. Verify this is a DoD or DoD-approved CA. This will ensure the router has enrolled and received a certificate from a trusted CA. The CA trust point configuration would look similar to the example below.

crypto pki trustpoint CA_X
 enrollment url http://trustpoint1.example.com

Note: A remote end-point's certificate will always be validated by the router by verifying the signature of the CA on the certificate using the CA's public key, which is contained in the router's certificate it received at enrollment.

Note: This requirement is not applicable if the router does not have any public key certificates.

If the Cisco router is not configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider, this is a finding."
  desc 'fix', 'Configure the router to obtain its public key certificates from an appropriate certificate policy through an approved service provider as shown in the example below.

R2(config)# crypto pki trustpoint CA_X
R2(ca-trustpoint)#enrollment url http://trustpoint1.example.com'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17095r287607_chk'
  tag severity: 'medium'
  tag gid: 'V-215856'
  tag rid: 'SV-215856r531083_rule'
  tag stig_id: 'CISC-ND-001440'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-17093r287608_fix'
  tag 'documentable'
  tag legacy: ['SV-105501', 'V-96363']
  tag cci: ['CCI-001159', 'CCI-000366']
  tag nist: ['SC-17 a', 'CM-6 b']
end

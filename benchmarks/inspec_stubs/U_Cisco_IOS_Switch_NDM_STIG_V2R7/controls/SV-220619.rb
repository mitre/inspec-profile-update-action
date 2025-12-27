control 'SV-220619' do
  title 'The Cisco switch must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'Each organization obtains user certificates from an approved, shared service provider as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority (CA) at medium assurance or higher, this CA will suffice.'
  desc 'check', "Review the switch configuration to determine if a CA trust point has been configured. The CA trust point will contain the URL of the CA in which the switch has enrolled. Verify this is a DoD or DoD-approved CA. This will ensure the switch has enrolled and received a certificate from a trusted CA. The CA trust point configuration would look similar to the example below:

crypto pki trustpoint CA_X
 enrollment url http://trustpoint1.example.com

Note: A remote endpoint's certificate will always be validated by the switch by verifying the signature of the CA on the certificate using the CA's public key, which is contained in the switch's certificate that it received at enrollment.

If the Cisco switch is not configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider, this is a finding."
  desc 'fix', 'Configure the switch to obtain its public key certificates from an appropriate certificate policy through an approved service provider as show in the example below:

SW2(ca-trustpoint)#enrollment url http://trustpoint1.example.com'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22334r507903_chk'
  tag severity: 'medium'
  tag gid: 'V-220619'
  tag rid: 'SV-220619r879887_rule'
  tag stig_id: 'CISC-ND-001440'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-22323r507904_fix'
  tag 'documentable'
  tag legacy: ['SV-110467', 'V-101363']
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end

control 'SV-220567' do
  title 'The Cisco switch must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', "Review the switch configuration to determine if a CA trust point has been configured. The CA trust point will contain the URL of the CA in which the switch has enrolled with. Verify this is a DoD or DoD-approved CA. This will ensure the switch has enrolled and received a certificate from a trusted CA. The CA trust point configuration would look similar to the example below:

crypto pki trustpoint CA_X
 enrollment url http://trustpoint1.example.com

Note: A remote end-point's certificate will always be validated by the switch by verifying the signature of the CA on the certificate using the CA's public key, which is contained in the switch's certificate it received at enrollment.

If the Cisco switch is not configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider, this is a finding."
  desc 'fix', 'Configure the switch to obtain its public key certificates from an appropriate certificate policy through an approved service provider as show in the example below:

SW2(ca-trustpoint)#enrollment url http://trustpoint1.example.com'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22282r508645_chk'
  tag severity: 'medium'
  tag gid: 'V-220567'
  tag rid: 'SV-220567r531084_rule'
  tag stig_id: 'CISC-ND-001440'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-22271r508646_fix'
  tag 'documentable'
  tag legacy: ['V-101485', 'SV-110589']
  tag cci: ['CCI-001159', 'CCI-000366']
  tag nist: ['SC-17 a', 'CM-6 b']
end

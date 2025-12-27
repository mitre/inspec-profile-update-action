control 'SV-220515' do
  title 'The Cisco switch must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'If PKI certificates are not implemented on the switch, this requirement is not applicable.

Step 1: Review the switch configuration to determine if a CA trust point has been configured as shown in the example below:

crypto ca trustpoint CA_X 
 enrollment terminal

Step 2: Verify the CA is a DoD or DoD-approved service provider by entering the following command: show crypto ca certificates

The output will list the following information for each certificate:

Trustpoint (will map to a configured trustpoint from step 1)
Common Name (CN) of the issuer
Organization (O) of the issuer
Organization Unit (OU) of the issuer
Note: Cisco NX-OS software supports only the manual cut-and-paste method for certificate enrollment
If the switch is not configured to obtain its public key certificates from a DoD or DoD-approved service provider, this is a finding.'
  desc 'fix', 'Ensure that certificate requests are only sent to DoD or DoD-approved service providers.'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22230r539266_chk'
  tag severity: 'medium'
  tag gid: 'V-220515'
  tag rid: 'SV-220515r879887_rule'
  tag stig_id: 'CISC-ND-001440'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-22219r539267_fix'
  tag 'documentable'
  tag legacy: ['SV-110679', 'V-101575']
  tag cci: ['CCI-001159', 'CCI-000366']
  tag nist: ['SC-17 a', 'CM-6 b']
end

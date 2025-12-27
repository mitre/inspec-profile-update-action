control 'SV-239942' do
  title 'The Cisco ASA must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'If PKI certificates are not implemented on the ASA, this requirement is not applicable.

Step 1: Review the ASA configuration to determine if a CA trust point has been configured as shown in the example below.

Step 2: Verify the CA is a DoD or DoD-approved service provider by entering the following command.

show crypto ca certificates

The output will list the following information for each certificate:
Associated Trustpoints:  (will map to a configured trustpoint from Step 1)
Common Name (CN) of the issuer
Organization Unit (OU) of the issuer
Organization (O) of the issuer
 Validity Date

If the ASA is not configured to obtain its public key certificates from a DoD or DoD-approved service provider, this is a finding.'
  desc 'fix', 'Ensure certificate requests are only sent to DoD or DoD-approved service providers.'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43175r666187_chk'
  tag severity: 'medium'
  tag gid: 'V-239942'
  tag rid: 'SV-239942r666189_rule'
  tag stig_id: 'CASA-ND-001370'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-43134r666188_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end

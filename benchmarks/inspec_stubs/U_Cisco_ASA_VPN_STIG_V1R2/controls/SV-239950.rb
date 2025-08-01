control 'SV-239950' do
  title 'The Cisco ASA must be configured to not accept certificates that have been revoked when using PKI for authentication.'
  desc 'Situations may arise in which the certificate issued by a Certificate Authority (CA) may need to be revoked before the lifetime of the certificate expires. For example, the certificate is known to have been compromised.

When an incoming Internet Key Exchange (IKE) session is initiated for a remote client or peer whose certificate is revoked, the revocation list configured for use by the VPN server is checked to see if the certificate is valid; if the certificate is revoked, IKE will fail and an IPsec security association will not be established for the remote endpoint.'
  desc 'check', "If PKI certificates are not implemented on the ASA, this requirement is not applicable.

Verify the ASA does not accept certificates that have been revoked.

Revocation checking using CRL example:

crypto ca trustpoint CA_X
 revocation-check crl

Note: By default, the ASA will use the distribution points listed in CDP extension of the certificate that is being validated. 

Revocation checking using OCSP example:

crypto ca trustpoint CA_X
 revocation-check ocsp

Note: By default, the ASA will use the OSCP responder address found in the Authority Information Access (AIA) field of the client's certificate. Deployment with CAC would be an exception.

If the ASA accepts certificates that have been revoked, this is a finding."
  desc 'fix', 'Configure the ASA to not accept certificates that have been revoked.

Revocation checking using CRL example:

ASA1(config)# crypto ca trustpoint CA_X
ASA1(config-ca-trustpoint)# revocation-check crl
ASA1(config-ca-crl)# end

Revocation checking using OCSP example:

ASA1(config)# crypto ca trustpoint CA_X
ASA1(config-ca-trustpoint)# revocation-check ocsp
ASA1(config-ca-crl)# end'
  impact 0.7
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43183r666254_chk'
  tag severity: 'high'
  tag gid: 'V-239950'
  tag rid: 'SV-239950r666256_rule'
  tag stig_id: 'CASA-VN-000130'
  tag gtitle: 'SRG-NET-000512-VPN-002230'
  tag fix_id: 'F-43142r666255_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

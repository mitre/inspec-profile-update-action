control 'SV-242257' do
  title 'The TippingPoint SMS must obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'In the SMS client, ensure the certificate is signed by an authorized DoD Certificate Authority. 

Select Admin >> Certificate Management >> Certificates.

If there is no certificate, or the certificate is signed by a CA that is not authorized in the DoD, this is a finding.'
  desc 'fix', 'In the SMS client, ensure the certificate is signed by an authorized DoD Certificate Authority. 

1. Select Admin >> Certificate Management >> Certificates.
2. Select import. 
3. The SMS can import a certificate with a private key file separately, or can import a PKCS12/PFX file. The user can use OpenSSL on a separate system to generate the certificate signing request (CSR) or can use the CSR generation tool on the SMS under Admin, Certificate Management, Signing Requests. The CSR must ensure the following attributes are added to the CSR if using the SMS tool: 2048 RSA key size and a DNS Subject Alternative Name (SAN) - if required.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45532r710776_chk'
  tag severity: 'medium'
  tag gid: 'V-242257'
  tag rid: 'SV-242257r710778_rule'
  tag stig_id: 'TIPP-NM-000600'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-45490r710777_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end

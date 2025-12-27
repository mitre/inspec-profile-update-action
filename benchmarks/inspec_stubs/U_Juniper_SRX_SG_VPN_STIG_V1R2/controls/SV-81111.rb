control 'SV-81111' do
  title 'The Juniper SRX Services Gateway VPN must not accept certificates that have been revoked when using PKI for authentication.'
  desc 'Situations may arise in which the certificate issued by a Certificate Authority (CA) may need to be revoked before the lifetime of the certificate expires. For example, the certificate is known to have been compromised. 

To achieve this, a list of certificates that have been revoked, known as a Certificate Revocation List (CRL), is sent periodically from the CA to the IPsec gateway. When an incoming Internet Key Exchange (IKE) session is initiated for a remote client or peer whose certificate is revoked, the CRL will be checked to see if the certificate is valid; if the certificate is revoked, IKE will fail and an IPsec security association will not be established for the remote endpoint.'
  desc 'check', 'Examine the CA trust point defined on the VPN gateway to determine if it references a CRL and that revocation check has been enabled. An alternate mechanism for checking the validity of a certificate is the use of the Online Certificate Status Protocol (OCSP). Unlike CRLs, which provide only periodic certificate status checks, OCSP can provide timely information regarding the status of a certificate.

If revoked certificates are accepted for PKI authentication, this is a finding.'
  desc 'fix', 'Configure the CA trust point to enable certificate revocation check by referencing a CRL or via OCSP.'
  impact 0.7
  ref 'DPMS Target Juniper SRX SG VPN'
  tag check_id: 'C-67247r1_chk'
  tag severity: 'high'
  tag gid: 'V-66621'
  tag rid: 'SV-81111r1_rule'
  tag stig_id: 'JUSX-VN-000012'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-72697r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

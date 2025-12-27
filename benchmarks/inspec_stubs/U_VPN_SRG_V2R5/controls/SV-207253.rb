control 'SV-207253' do
  title 'The VPN Gateway must not accept certificates that have been revoked when using PKI for authentication.'
  desc 'Situations may arise in which the certificate issued by a Certificate Authority (CA) may need to be revoked before the lifetime of the certificate expires. For example, the certificate is known to have been compromised.

When an incoming Internet Key Exchange (IKE) session is initiated for a remote client or peer whose certificate is revoked, the revocation list configured for use by the VPN server is checked to see if the certificate is valid; if the certificate is revoked, IKE will fail and an IPsec security association will not be established for the remote endpoint.'
  desc 'check', 'Verify the VPN Gateway does not accept certificates that have been revoked when using PKI for authentication.

If the VPN Gateway accepts certificates that have been revoked when using PKI for authentication, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to not accept certificates that have been revoked when using PKI for authentication.'
  impact 0.7
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7513r378380_chk'
  tag severity: 'high'
  tag gid: 'V-207253'
  tag rid: 'SV-207253r608988_rule'
  tag stig_id: 'SRG-NET-000512-VPN-002230'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7513r378381_fix'
  tag 'documentable'
  tag legacy: ['V-97201', 'SV-106339']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

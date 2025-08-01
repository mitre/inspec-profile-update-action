control 'SV-48385' do
  title 'The system must query the certification authority to determine whether a public key certificate has been revoked before accepting the certificate for authentication purposes.'
  desc "Failure to verify a certificate's revocation status can result in the system accepting a revoked and therefore unauthorized, certificate.  This could result in the installation of unauthorized software or a connection for rogue networks, depending on the use for which the certificate is intended.   Querying for certificate revocation mitigates the risk that the system will accept an unauthorized certificate."
  desc 'check', 'Verify the system has software installed and running that provides certificate validation and revocation checking.  If it does not, this is a finding.'
  desc 'fix', 'Install software that  provides certificate validation and revocation checking.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45054r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36736'
  tag rid: 'SV-48385r2_rule'
  tag stig_id: 'WN08-GE-000030'
  tag gtitle: 'WINGE-000030'
  tag fix_id: 'F-41516r1_fix'
  tag 'documentable'
  tag ia_controls: 'IATS-1, IATS-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

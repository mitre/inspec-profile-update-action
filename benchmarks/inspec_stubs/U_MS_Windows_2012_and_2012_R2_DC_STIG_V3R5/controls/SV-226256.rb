control 'SV-226256' do
  title 'The system must query the certification authority to determine whether a public key certificate has been revoked before accepting the certificate for authentication purposes.'
  desc "Failure to verify a certificate's revocation status can result in the system accepting a revoked, and therefore unauthorized, certificate.  This could result in the installation of unauthorized software or a connection for rogue networks, depending on the use for which the certificate is intended.   Querying for certificate revocation mitigates the risk that the system will accept an unauthorized certificate."
  desc 'check', 'Verify the system has software installed and running that provides certificate validation and revocation checking.  If it does not, this is a finding.'
  desc 'fix', 'Install software that  provides certificate validation and revocation checking.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27958r476612_chk'
  tag severity: 'medium'
  tag gid: 'V-226256'
  tag rid: 'SV-226256r794542_rule'
  tag stig_id: 'WN12-GE-000025'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-27946r476613_fix'
  tag 'documentable'
  tag legacy: ['SV-51584', 'V-36736']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

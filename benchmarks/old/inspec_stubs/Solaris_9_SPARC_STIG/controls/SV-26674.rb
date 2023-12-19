control 'SV-26674' do
  title 'The rexecd service must not be installed.'
  desc 'The rexecd process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'fix', 'Remove the SUNWrcmdr package.

Procedure:
# pkgrm SUNWrcmdr'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22434'
  tag rid: 'SV-26674r1_rule'
  tag stig_id: 'GEN003845'
  tag gtitle: 'GEN003845'
  tag fix_id: 'F-23910r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end

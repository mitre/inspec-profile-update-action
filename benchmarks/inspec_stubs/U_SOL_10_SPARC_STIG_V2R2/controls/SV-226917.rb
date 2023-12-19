control 'SV-226917' do
  title 'The rshd service must not be installed.'
  desc 'The rshd process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', 'Check if the SUNWrcmdr package is installed.

Procedure:
# pkginfo SUNWrcmdr

If the package is installed, this is a finding.'
  desc 'fix', 'Remove the SUNWrcmdr package.

Procedure:
# pkgrm SUNWrcmdr'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29079r485044_chk'
  tag severity: 'medium'
  tag gid: 'V-226917'
  tag rid: 'SV-226917r603265_rule'
  tag stig_id: 'GEN003825'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-29067r485045_fix'
  tag 'documentable'
  tag legacy: ['V-22431', 'SV-26668']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

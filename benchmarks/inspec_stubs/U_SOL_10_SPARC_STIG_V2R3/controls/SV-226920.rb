control 'SV-226920' do
  title 'The rexecd service must not be installed.'
  desc 'The rexecd process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', 'Check if the SUNWrcmdr package is installed.

Procedure:
# pkginfo SUNWrcmdr

If the package is installed, this is a finding.'
  desc 'fix', 'Remove the SUNWrcmdr package.

Procedure:
# pkgrm SUNWrcmdr'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29082r485056_chk'
  tag severity: 'medium'
  tag gid: 'V-226920'
  tag rid: 'SV-226920r603265_rule'
  tag stig_id: 'GEN003845'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-29070r485057_fix'
  tag 'documentable'
  tag legacy: ['SV-26674', 'V-22434']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

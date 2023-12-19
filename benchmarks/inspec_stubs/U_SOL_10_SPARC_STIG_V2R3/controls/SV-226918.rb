control 'SV-226918' do
  title 'The rlogind service must not be installed.'
  desc 'The rlogind process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', 'Check if the SUNWrcmdr package is installed.

Procedure:
# pkginfo SUNWrcmdr

If the package is installed, this is a finding.'
  desc 'fix', 'Remove the SUNWrcmdr package.

Procedure:
# pkgrm SUNWrcmdr'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29080r485050_chk'
  tag severity: 'medium'
  tag gid: 'V-226918'
  tag rid: 'SV-226918r603265_rule'
  tag stig_id: 'GEN003835'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-29068r485051_fix'
  tag 'documentable'
  tag legacy: ['SV-26670', 'V-22433']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

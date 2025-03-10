control 'SV-227823' do
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
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29985r489835_chk'
  tag severity: 'medium'
  tag gid: 'V-227823'
  tag rid: 'SV-227823r603266_rule'
  tag stig_id: 'GEN003835'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-29973r489836_fix'
  tag 'documentable'
  tag legacy: ['V-22433', 'SV-26670']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

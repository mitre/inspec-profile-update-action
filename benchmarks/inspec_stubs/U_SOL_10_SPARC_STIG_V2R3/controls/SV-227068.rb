control 'SV-227068' do
  title 'The system must have USB disabled unless needed.'
  desc 'USB is a common computer peripheral interface.  USB devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', 'If the system needs USB, this vulnerability is not applicable.
Verify the SUNWusb package is installed.
# pkginfo SUNWusb
If the package is installed, this is a finding.'
  desc 'fix', 'Remove the SUNWusb package.
# pkgrm SUNWusb'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29230r485582_chk'
  tag severity: 'low'
  tag gid: 'V-227068'
  tag rid: 'SV-227068r603265_rule'
  tag stig_id: 'GEN008460'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29218r485583_fix'
  tag 'documentable'
  tag legacy: ['V-22578', 'SV-26968']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

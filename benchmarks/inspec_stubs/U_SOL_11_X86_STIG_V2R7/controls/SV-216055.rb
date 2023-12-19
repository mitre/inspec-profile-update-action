control 'SV-216055' do
  title 'The FTP daemon must not be installed unless required.'
  desc 'FTP is an insecure protocol.'
  desc 'check', 'Determine if the FTP package is installed.

# pkg list service/network/ftp

If an installed package named "service/network/ftp" is listed and not required for operations, this is a finding.'
  desc 'fix', 'The Software Installation Profile is required.

# pfexec pkg uninstall service/network/ftp'
  impact 0.7
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17293r372547_chk'
  tag severity: 'high'
  tag gid: 'V-216055'
  tag rid: 'SV-216055r603268_rule'
  tag stig_id: 'SOL-11.1-020130'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17291r372548_fix'
  tag 'documentable'
  tag legacy: ['V-47911', 'SV-60783']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

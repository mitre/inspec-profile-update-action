control 'SV-216051' do
  title 'The finger daemon package must not be installed.'
  desc 'Finger is an insecure protocol.'
  desc 'check', 'Determine if the finger package is installed.

# pkg list service/network/finger

If an installed package named service/network/finger is listed, this is a finding.'
  desc 'fix', 'The Software Installation Profile is required.

# pfexec pkg uninstall service/network/finger'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17289r372535_chk'
  tag severity: 'low'
  tag gid: 'V-216051'
  tag rid: 'SV-216051r603268_rule'
  tag stig_id: 'SOL-11.1-020090'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17287r372536_fix'
  tag 'documentable'
  tag legacy: ['V-47893', 'SV-60765']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

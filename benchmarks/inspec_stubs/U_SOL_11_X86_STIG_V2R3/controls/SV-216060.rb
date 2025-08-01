control 'SV-216060' do
  title 'The VNC server package must not be installed unless required.'
  desc 'The VNC service uses weak authentication capabilities and provides the user complete graphical system access.'
  desc 'check', 'Determine if the VNC server package is installed.

# pkg list x11/server/xvnc

If an installed package named "x11/server/xvnc is listed" is listed, this is a finding.'
  desc 'fix', 'The Software Installation Profile is required.

# pfexec pkg uninstall x11/server/xvnc'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17298r372562_chk'
  tag severity: 'medium'
  tag gid: 'V-216060'
  tag rid: 'SV-216060r603268_rule'
  tag stig_id: 'SOL-11.1-020180'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17296r372563_fix'
  tag 'documentable'
  tag legacy: ['V-47921', 'SV-60793']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

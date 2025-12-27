control 'SV-216295' do
  title 'The VNC server package must not be installed unless required.'
  desc 'The VNC service uses weak authentication capabilities and provides the user complete graphical system access.'
  desc 'check', 'Determine if the VNC server package is installed.

# pkg list x11/server/xvnc

If an installed package named "x11/server/xvnc is listed" is listed, this is a finding.'
  desc 'fix', 'The Software Installation Profile is required.

# pfexec pkg uninstall x11/server/xvnc'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17531r370973_chk'
  tag severity: 'medium'
  tag gid: 'V-216295'
  tag rid: 'SV-216295r603267_rule'
  tag stig_id: 'SOL-11.1-020180'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17529r370974_fix'
  tag 'documentable'
  tag legacy: ['SV-60793', 'V-47921']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

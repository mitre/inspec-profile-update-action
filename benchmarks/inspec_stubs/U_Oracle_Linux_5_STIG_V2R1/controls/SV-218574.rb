control 'SV-218574' do
  title '.Xauthority or X*.hosts (or equivalent) file(s) must be used to restrict access to the X server.'
  desc "If access to the X server is not restricted, a user's X session may be compromised."
  desc 'check', 'Determine if the X server is running.
Procedure:
# ps -ef |grep X

Determine if xauth is being used.
Procedure:
# xauth
xauth> list

If the above command sequence does not show any host other than the localhost, then xauth is not being used.

Search the system for an X*.hosts file, where "*" is a display number used to limit X window connections. If no files are found, X*.hosts files are not being used. If the X*.hosts files contain any unauthorized hosts, this is a finding.

If both xauth and X*.hosts files are not being used, this is a finding.'
  desc 'fix', 'Create an X*.hosts file, where "*" is a display number used to limit X window connections. Add the list of authorized X clients to the file.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20049r555920_chk'
  tag severity: 'medium'
  tag gid: 'V-218574'
  tag rid: 'SV-218574r603259_rule'
  tag stig_id: 'GEN005220'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20047r555921_fix'
  tag 'documentable'
  tag legacy: ['V-12016', 'SV-63313']
  tag cci: ['CCI-000366', 'CCI-000297']
  tag nist: ['CM-6 b', 'CM-2 b 2']
end

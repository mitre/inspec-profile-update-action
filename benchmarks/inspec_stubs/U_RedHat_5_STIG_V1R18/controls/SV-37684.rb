control 'SV-37684' do
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
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36875r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12016'
  tag rid: 'SV-37684r1_rule'
  tag stig_id: 'GEN005220'
  tag gtitle: 'GEN005220'
  tag fix_id: 'F-31858r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000297']
  tag nist: ['CM-2 b 2']
end

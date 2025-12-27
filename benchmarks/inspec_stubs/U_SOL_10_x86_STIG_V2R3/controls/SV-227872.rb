control 'SV-227872' do
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

Search the system for an X*.hosts files, where * is a display number that may be used to limit X window connections.  If no files are found, X*.hosts files are not being used.  If the X*.hosts files contain any unauthorized hosts, this is a finding.

If both xauth and X*.hosts files are not being used, this is a finding.'
  desc 'fix', 'Create an X*.hosts file, where * is a display number that may be used to limit X window connections.  Add the list of authorized X clients to the file.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30034r490012_chk'
  tag severity: 'medium'
  tag gid: 'V-227872'
  tag rid: 'SV-227872r603266_rule'
  tag stig_id: 'GEN005220'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30022r490013_fix'
  tag 'documentable'
  tag legacy: ['V-12016', 'SV-12517']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-216312' do
  title '.Xauthority or X*.hosts (or equivalent) file(s) must be used to restrict access to the X server.'
  desc "If access to the X server is not restricted, a user's X session may be compromised."
  desc 'check', 'If X Display Manager (XDM) is not used on the system, this is not applicable.

Determine if XDM is running. 

Procedure:
# ps -ef | grep xdm

Determine if xauth is being used. 

Procedure:
# xauth 
xauth> list

If the above command sequence does not show any host other than the localhost, then xauth is not being used.

Search the system for an X*.hosts files, where * is a display number that may be used to limit X window connections. 

If no files are found, X*.hosts files are not being used. 

If the X*.hosts files contain any unauthorized hosts, this is a finding.

If both xauth and X*.hosts files are not being used, this is a finding.'
  desc 'fix', 'Create an X*.hosts file, where * is a display number that may be used to limit X window connections. 

Add the list of authorized X clients to the file.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17548r622320_chk'
  tag severity: 'medium'
  tag gid: 'V-216312'
  tag rid: 'SV-216312r603857_rule'
  tag stig_id: 'SOL-11.1-020540'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17546r371025_fix'
  tag 'documentable'
  tag legacy: ['SV-75495', 'V-61027']
  tag cci: ['CCI-000297', 'CCI-000366']
  tag nist: ['CM-2 b 2', 'CM-6 b']
end

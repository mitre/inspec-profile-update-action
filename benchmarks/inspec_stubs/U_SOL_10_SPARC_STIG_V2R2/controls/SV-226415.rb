control 'SV-226415' do
  title 'The /usr/aset/userlist file must be owned by root.'
  desc 'If the userlist file is not owned by root, then an unauthorized user can modify the file and enter an unauthorized user.'
  desc 'check', 'If ASET is not used on the system, this is not applicable.

Check the ownership of the /usr/aset/userlist file.
# ls -lL /usr/aset/userlist
If the owner of the file is not root, this is a finding.'
  desc 'fix', 'Use the chmod command to change the owner of the /usr/aset/userlist file.  

# chown root /usr/aset/userlist'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28576r482606_chk'
  tag severity: 'medium'
  tag gid: 'V-226415'
  tag rid: 'SV-226415r603265_rule'
  tag stig_id: 'GEN000000-SOL00240'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28564r482607_fix'
  tag 'documentable'
  tag legacy: ['SV-956', 'V-956']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

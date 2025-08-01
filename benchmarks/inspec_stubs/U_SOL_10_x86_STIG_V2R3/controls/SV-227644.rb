control 'SV-227644' do
  title 'The /etc/group file must be owned by root.'
  desc 'The /etc/group file is critical to system security and must be owned by a privileged user.  The group file contains a list of system groups and associated information.'
  desc 'check', 'Verify the /etc/group file is owned by root.

Procedure:
# ls -l /etc/group
If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/group file to root.

# chown root /etc/group'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29806r488492_chk'
  tag severity: 'medium'
  tag gid: 'V-227644'
  tag rid: 'SV-227644r603266_rule'
  tag stig_id: 'GEN001391'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29794r488493_fix'
  tag 'documentable'
  tag legacy: ['V-22335', 'SV-26431']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

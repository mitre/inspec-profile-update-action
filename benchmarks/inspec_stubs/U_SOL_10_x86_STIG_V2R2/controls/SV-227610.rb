control 'SV-227610' do
  title 'System files and directories must not have uneven access permissions.'
  desc 'Discretionary access control is undermined if users, other than a file owner, have greater access permissions to system files and directories than the owner.'
  desc 'check', 'Check system directories for uneven file permissions. 
Procedure:
 # ls -lL /etc /bin /usr/bin /usr/ucb /sbin /usr/sbin 

Uneven file permissions exist if the file owner has less permissions than the group or other user classes. If any of the files in the above listed directories contain uneven file permissions, this is a finding.'
  desc 'fix', 'Change the mode of files with uneven permissions so owners do not have less permission than group or world users.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29772r488387_chk'
  tag severity: 'medium'
  tag gid: 'V-227610'
  tag rid: 'SV-227610r603266_rule'
  tag stig_id: 'GEN001140'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29760r488388_fix'
  tag 'documentable'
  tag legacy: ['V-784', 'SV-39833']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end

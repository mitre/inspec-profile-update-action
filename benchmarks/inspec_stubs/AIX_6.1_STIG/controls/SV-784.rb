control 'SV-784' do
  title 'System files and directories must not have uneven access permissions.'
  desc 'Discretionary access control is undermined if users, other than a file owner, have greater access permissions to system files and directories than the owner.'
  desc 'check', 'Check system directories for uneven file permissions.

Procedure:
# ls -lL /etc /bin /usr/bin /usr/lbin /usr/ucb /sbin /usr/sbin

Uneven file permissions exist if the file owner has less permissions than the group or other user classes. If any of the files in the above listed directories contain uneven file permissions, this is a finding.'
  desc 'fix', 'Change the mode of files with uneven permissions so owners do not have less permission than group or world users.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-289r2_chk'
  tag severity: 'medium'
  tag gid: 'V-784'
  tag rid: 'SV-784r2_rule'
  tag stig_id: 'GEN001140'
  tag gtitle: 'GEN001140'
  tag fix_id: 'F-24427r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

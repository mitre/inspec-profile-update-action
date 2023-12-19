control 'SV-218260' do
  title 'System files and directories must not have uneven access permissions.'
  desc 'Discretionary access control is undermined if users, other than a file owner, have greater access permissions to system files and directories than the owner.'
  desc 'check', 'Check system directories for uneven file permissions.

Procedure:
# ls -lL /etc /bin /usr/bin /usr/lbin /usr/usb /sbin /usr/sbin

Uneven file permissions exist if the file owner has less permissions than the group or other user classes. If any of the files in the above listed directories contain uneven file permissions, this is a finding.'
  desc 'fix', 'Change the mode of files with uneven permissions so owners do not have less permission than group or world users.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19735r561428_chk'
  tag severity: 'medium'
  tag gid: 'V-218260'
  tag rid: 'SV-218260r603259_rule'
  tag stig_id: 'GEN001140'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19733r561429_fix'
  tag 'documentable'
  tag legacy: ['V-784', 'SV-64461']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end

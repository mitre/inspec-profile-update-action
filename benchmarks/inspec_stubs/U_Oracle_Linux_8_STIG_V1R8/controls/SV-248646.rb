control 'SV-248646' do
  title 'All OL 8 files and directories must have a valid owner.'
  desc 'Unowned files and directories may be unintentionally inherited if a user is assigned the same User Identifier "UID" as the UID of the unowned files.'
  desc 'check', 'Verify all files and directories on OL 8 have a valid owner with the following command: 
 
$ sudo find / -nouser 
 
If any files on the system do not have an assigned owner, this is a finding.'
  desc 'fix', 'Either remove all files and directories from the system that do not have a valid user or assign a valid user to all unowned files and directories on OL 8 with the "chown" command: 
 
$ sudo chown <user> <file>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52080r779502_chk'
  tag severity: 'medium'
  tag gid: 'V-248646'
  tag rid: 'SV-248646r779504_rule'
  tag stig_id: 'OL08-00-010780'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52034r779503_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

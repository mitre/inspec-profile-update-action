control 'SV-248567' do
  title 'OL 8 system commands must have mode 755 or less permissive.'
  desc 'If OL 8 were to allow any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to OL 8 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Verify the system commands contained in the following directories have mode "755" or less permissive with the following command: 
 
$ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -exec ls -l {} \\;
 
If any system commands are found to be group-writable or world-writable, this is a finding.'
  desc 'fix', 'Configure the system commands to be protected from unauthorized access. 
 
Run the following command, replacing "[FILE]" with any system command with a mode more permissive than "755". 
 
$ sudo chmod 755 [FILE]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52001r818620_chk'
  tag severity: 'medium'
  tag gid: 'V-248567'
  tag rid: 'SV-248567r818622_rule'
  tag stig_id: 'OL08-00-010300'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-51955r818621_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end

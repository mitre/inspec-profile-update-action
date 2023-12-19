control 'SV-248570' do
  title 'OL 8 library files must have mode 755 or less permissive.'
  desc 'If OL 8 were to allow any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to OL 8 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Verify the system-wide shared library files contained in the following directories have mode "755" or less permissive with the following command: 
 
$ sudo find -L /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type f -exec ls -l {} \\;

If any system-wide shared library file is found to be group-writable or world-writable, this is a finding.'
  desc 'fix', 'Configure the library files to be protected from unauthorized access. Run the following command, replacing "[FILE]" with any library file with a mode more permissive than 755. 
 
$ sudo chmod 755 [FILE]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52004r818626_chk'
  tag severity: 'medium'
  tag gid: 'V-248570'
  tag rid: 'SV-248570r818628_rule'
  tag stig_id: 'OL08-00-010330'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-51958r818627_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end

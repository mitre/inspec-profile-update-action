control 'SV-238377' do
  title 'The Ubuntu operating system must have system commands owned by root or a system account.'
  desc 'If the Ubuntu operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to Ubuntu operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system commands contained in the following directories are owned by root, or a required system account: 
 
/bin 
/sbin 
/usr/bin 
/usr/sbin 
/usr/local/bin 
/usr/local/sbin 
 
Use the following command for the check: 
 
$ sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \; 
 
If any system commands are returned and are not owned by a required system account, this is a finding.)
  desc 'fix', 'Configure the system commands and their respective parent directories to be protected from unauthorized access. Run the following command, replacing "[FILE]" with any system command file not owned by "root" or a required system account: 
 
$ sudo chown root [FILE]'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag check_id: 'C-41587r832966_chk'
  tag severity: 'medium'
  tag gid: 'V-238377'
  tag rid: 'SV-238377r832968_rule'
  tag stig_id: 'UBTU-20-010457'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-41546r832967_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end

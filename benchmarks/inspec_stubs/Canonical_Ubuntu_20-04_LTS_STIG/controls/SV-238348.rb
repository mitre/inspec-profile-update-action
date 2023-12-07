control 'SV-238348' do
  title 'The Ubuntu operating system library directories must have mode 0755 or less permissive.'
  desc 'If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system-wide shared library directories "/lib", "/lib64", and "/usr/lib have mode 0755 or less permissive with the following command: 
 
$ sudo find /lib /lib64 /usr/lib -perm /022 -type d -exec stat -c "%n %a" '{}' \; 
 
If any of the aforementioned directories are found to be group-writable or world-writable, this is a finding.)
  desc 'fix', "Configure the shared library directories to be protected from unauthorized access. Run the following command: 
 
$ sudo find /lib /lib64 /usr/lib -perm /022 -type d -exec chmod 755 '{}' \\;"
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag check_id: 'C-41558r654217_chk'
  tag severity: 'medium'
  tag gid: 'V-238348'
  tag rid: 'SV-238348r654219_rule'
  tag stig_id: 'UBTU-20-010427'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-41517r654218_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end

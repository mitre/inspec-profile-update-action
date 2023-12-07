control 'SV-238347' do
  title 'The Ubuntu operating system library files must have mode 0755 or less permissive.'
  desc 'If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process. 
 
This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system-wide shared library files contained in the directories "/lib", "/lib64", and "/usr/lib" have mode 0755 or less permissive with the following command: 
 
$ sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c "%n %a" '{}' \; 
/usr/lib64/pkcs11-spy.so 
 
If any files are found to be group-writable or world-writable, this is a finding.)
  desc 'fix', "Configure the library files to be protected from unauthorized access. Run the following command: 
 
$ sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec chmod 755 '{}' \\;"
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag check_id: 'C-41557r654214_chk'
  tag severity: 'medium'
  tag gid: 'V-238347'
  tag rid: 'SV-238347r654216_rule'
  tag stig_id: 'UBTU-20-010426'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-41516r654215_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end

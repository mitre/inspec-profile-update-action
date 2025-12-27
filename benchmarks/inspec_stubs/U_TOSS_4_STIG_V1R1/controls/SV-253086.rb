control 'SV-253086' do
  title 'TOSS must limit privileges to change software resident within software libraries.'
  desc 'If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to TOSS with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Verify the system commands contained in the following directories are owned by "root" or an appropriate system account with the following command:

$ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -exec ls -l {} \\;

If any system commands are returned which are not owned by an appropriate system account, this is a finding.

Verify the system-wide shared library files are owned by "root" or an appropriate system account with the following command:

$ sudo find -L /lib /lib64 /usr/lib /usr/lib64 ! -user root -exec ls -l {} \\;

If any system wide shared library file is returned which is not owned by an appropriate system account, this is a finding.'
  desc 'fix', 'Configure the system commands to be protected from unauthorized access.

Run the following command, replacing "[FILE]" with any system command file not owned by "root."

$ sudo chown root [FILE]

Configure the system-wide shared library files (/lib, /lib64, /usr/lib and /usr/lib64) to be protected from unauthorized access.

Run the following command, replacing "[FILE]" with any library file not owned by "root."

$ sudo chown root [FILE]'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56539r824928_chk'
  tag severity: 'medium'
  tag gid: 'V-253086'
  tag rid: 'SV-253086r824930_rule'
  tag stig_id: 'TOSS-04-040340'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-56489r824929_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end

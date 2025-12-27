control 'SV-252652' do
  title 'OL 8 library directories must be owned by root.'
  desc 'If OL 8 were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to OL 8 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals will be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system-wide shared library directories are owned by "root" with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d -exec stat -c "%n %U" '{}' \;

If any system wide shared library directory is returned, this is a finding.)
  desc 'fix', 'Configure the system-wide shared library directories within (/lib, /lib64, /usr/lib and /usr/lib64) to be protected from unauthorized access.

Run the following command, replacing "[DIRECTORY]" with any library directory not owned by "root".

$ sudo chown root [DIRECTORY]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-56108r818750_chk'
  tag severity: 'medium'
  tag gid: 'V-252652'
  tag rid: 'SV-252652r818752_rule'
  tag stig_id: 'OL08-00-010341'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-56058r818751_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end

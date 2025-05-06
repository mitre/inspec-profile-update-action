control 'SV-248572' do
  title 'OL 8 library files must be group-owned by root.'
  desc 'If OL 8 were to allow any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to OL 8 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Verify the system-wide shared library files are group-owned by "root" with the following command:

$ sudo find -L /lib /lib64 /usr/lib /usr/lib64 ! -group root -exec ls -l {} \\;

If any system-wide shared library file is returned, this is a finding.'
  desc 'fix', 'Configure the system-wide shared library files (/lib, /lib64, /usr/lib, and /usr/lib64) to be protected from unauthorized access.

Run the following command, replacing "[FILE]" with any library file not group-owned by "root".

$ sudo chgrp root [FILE]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52006r779280_chk'
  tag severity: 'medium'
  tag gid: 'V-248572'
  tag rid: 'SV-248572r779282_rule'
  tag stig_id: 'OL08-00-010350'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-51960r779281_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end

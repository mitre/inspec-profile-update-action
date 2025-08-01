control 'SV-237612' do
  title 'The SUSE operating system library directories must be group-owned by root.'
  desc 'If the SUSE operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to SUSE operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system-wide library directories "/lib", "/lib64", "/usr/lib" and "/usr/lib64" are group-owned by root.

Check that the system-wide library directories are group-owned by root with the following command:

> sudo find /lib /lib64 /usr/lib /usr/lib64 ! -group root -type d -exec stat -c "%n %G" '{}' \;

If any system wide shared library directory is returned, this is a finding.)
  desc 'fix', "Configure the system library directories to be protected from unauthorized access. Run the following command:

> sudo find /lib /lib64 /usr/lib /usr/lib64 ! -group root -type d -exec chgrp root '{}' \\;"
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-40831r646797_chk'
  tag severity: 'medium'
  tag gid: 'V-237612'
  tag rid: 'SV-237612r646799_rule'
  tag stig_id: 'SLES-12-010876'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-40794r646798_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end

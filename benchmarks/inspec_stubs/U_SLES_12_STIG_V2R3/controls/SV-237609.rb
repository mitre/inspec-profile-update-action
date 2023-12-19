control 'SV-237609' do
  title 'The SUSE operating system library files must be owned by root.'
  desc 'If the SUSE operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to SUSE operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system-wide shared library files contained in the directories "/lib", "/lib64", "/usr/lib" and "/usr/lib64" are owned by root.

Check that the system-wide shared library files are owned by root with the following command:

> sudo find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type f -exec stat -c "%n %U" '{}' \;

If any system wide library file is returned, this is a finding.)
  desc 'fix', "Configure the system library files to be protected from unauthorized access. Run the following command:

> sudo find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type f -exec chown root '{}' \\;"
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-40828r646788_chk'
  tag severity: 'medium'
  tag gid: 'V-237609'
  tag rid: 'SV-237609r646790_rule'
  tag stig_id: 'SLES-12-010873'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-40791r646789_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end

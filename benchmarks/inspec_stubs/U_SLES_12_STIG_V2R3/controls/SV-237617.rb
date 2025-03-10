control 'SV-237617' do
  title 'The SUSE operating system must have system commands group-owned by root.'
  desc 'If the SUSE operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to SUSE operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system commands contained in the following directories are group-owned by root:

/bin
/sbin
/usr/bin
/usr/sbin
/usr/local/bin
/usr/local/sbin

Run the check with the following command:

> sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f -exec stat -c "%n %G" '{}' \;

If any system commands are returned that are not Set Group ID up on execution (SGID) files and owned by a privileged account, this is a finding.)
  desc 'fix', "Configure the system commands to be protected from unauthorized access. Run the following command:

> sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f -exec chgrp root '{}' \\;"
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-40836r646812_chk'
  tag severity: 'medium'
  tag gid: 'V-237617'
  tag rid: 'SV-237617r646814_rule'
  tag stig_id: 'SLES-12-010882'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-40799r646813_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end

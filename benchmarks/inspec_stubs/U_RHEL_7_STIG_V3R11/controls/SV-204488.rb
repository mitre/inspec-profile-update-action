control 'SV-204488' do
  title 'The Red Hat Enterprise Linux operating system must set the umask value to 077 for all local interactive user accounts.'
  desc 'The umask controls the default access mode assigned to newly created files. A umask of 077 limits new files to mode 700 or less permissive. Although umask can be represented as a four-digit number, the first digit representing special access modes is typically ignored or required to be "0". This requirement applies to the globally configured system defaults and the local interactive user defaults for each account on the system.'
  desc 'check', %q(Verify that the default umask for all local interactive users is "077".

Identify the locations of all local interactive user home directories by looking at the "/etc/passwd" file.

Check all local interactive user initialization files for interactive users with the following command:

Note: The example is for a system that is configured to create users home directories in the "/home" directory.

$ sudo grep -ir ^umask /home | grep -v '.bash_history'

If any local interactive user initialization files are found to have a umask statement that has a value less restrictive than "077", this is a finding.)
  desc 'fix', %q(Remove the umask statement from all local interactive user's initialization files. 

If the account is for an application, the requirement for a umask less restrictive than "077" can be documented with the Information System Security Officer, but the user agreement for access to the account must specify that the local interactive user must log on to their account first and then switch the user to the application account with the correct option to gain the account's environment variables.)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4612r858483_chk'
  tag severity: 'medium'
  tag gid: 'V-204488'
  tag rid: 'SV-204488r861006_rule'
  tag stig_id: 'RHEL-07-021040'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-4612r88657_fix'
  tag 'documentable'
  tag legacy: ['V-72049', 'SV-86673']
  tag cci: ['CCI-000318', 'CCI-000368', 'CCI-001812', 'CCI-001813', 'CCI-001814']
  tag nist: ['CM-3 f', 'CM-6 c', 'CM-11 (2)', 'CM-5 (1) (a)', 'CM-5 (1)']
end

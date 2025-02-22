control 'SV-204469' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that all local interactive user home directories are owned by their respective users.'
  desc "If a local interactive user does not own their home directory, unauthorized users could access or modify the user's files, and the users may not be able to access their own files."
  desc 'check', %q(Verify the assigned home directory of all local interactive users on the system exists.

Check the home directory assignment for all local interactive users on the system with the following command:

# ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)

-rwxr-x--- 1 smithj users 18 Mar 5 17:06 /home/smithj

If any home directories referenced in "/etc/passwd" are not owned by the interactive user, this is a finding.)
  desc 'fix', %q(Change the owner of a local interactive user's home directories to that owner. To change the owner of a local interactive user's home directory, use the following command:

Note: The example will be for the user smithj, who has a home directory of "/home/smithj".

# chown smithj /home/smithj)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4593r622293_chk'
  tag severity: 'medium'
  tag gid: 'V-204469'
  tag rid: 'SV-204469r603830_rule'
  tag stig_id: 'RHEL-07-020640'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-4593r88600_fix'
  tag 'documentable'
  tag legacy: ['SV-86643', 'V-72019']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-209074' do
  title 'The Oracle Linux operating system must mount /dev/shm with the nosuid option.'
  desc 'The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify that the "nosuid" option is configured for /dev/shm.

Check that the operating system is configured to use the "nosuid" option for /dev/shm with the following command:

# cat /etc/fstab | grep /dev/shm | grep nosuid

tmpfs   /dev/shm   tmpfs   defaults,nodev,nosuid,noexec   0 0

If the "nosuid" option is not present on the line for "/dev/shm", this is a finding.

Verify "/dev/shm" is mounted with the "nosuid" option:

# mount | grep "/dev/shm" | grep nosuid

If no results are returned, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "nosuid" option for all lines containing "/dev/shm".'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9327r358007_chk'
  tag severity: 'low'
  tag gid: 'V-209074'
  tag rid: 'SV-209074r854334_rule'
  tag stig_id: 'OL6-00-000531'
  tag gtitle: 'SRG-OS-000368'
  tag fix_id: 'F-9327r358008_fix'
  tag 'documentable'
  tag legacy: ['SV-96173', 'V-81459']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end

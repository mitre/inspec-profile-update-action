control 'SV-218110' do
  title 'The Red Hat Enterprise Linux operating system must mount /dev/shm with the noexec option.'
  desc 'The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify that the "noexec" option is configured for /dev/shm.

Check that the operating system is configured to use the "noexec" option for /dev/shm with the following command:

# cat /etc/fstab | grep /dev/shm | grep noexec

tmpfs   /dev/shm   tmpfs   defaults,nodev,nosuid,noexec   0 0

If the "noexec" option is not present on the line for "/dev/shm", this is a finding.

Verify "/dev/shm" is mounted with the "noexec" option:

# mount | grep "/dev/shm" | grep noexec

If no results are returned, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "noexec" option for all lines containing "/dev/shm".'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19591r377345_chk'
  tag severity: 'low'
  tag gid: 'V-218110'
  tag rid: 'SV-218110r603264_rule'
  tag stig_id: 'RHEL-06-000532'
  tag gtitle: 'SRG-OS-000368'
  tag fix_id: 'F-19589r377346_fix'
  tag 'documentable'
  tag legacy: ['SV-96163', 'V-81449']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end

control 'SV-209073' do
  title 'The Oracle Linux operating system must mount /dev/shm with the nodev option.'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify that the "nodev" option is configured for /dev/shm.

Check that the operating system is configured to use the "nodev" option for /dev/shm with the following command:

# cat /etc/fstab | grep /dev/shm | grep nodev

tmpfs   /dev/shm   tmpfs   defaults,nodev,nosuid,noexec   0 0

If the "nodev" option is not present on the line for "/dev/shm", this is a finding.

Verify "/dev/shm" is mounted with the "nodev" option:

# mount | grep "/dev/shm" | grep nodev

If no results are returned, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "nodev" option for all lines containing "/dev/shm".'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9326r358004_chk'
  tag severity: 'low'
  tag gid: 'V-209073'
  tag rid: 'SV-209073r854333_rule'
  tag stig_id: 'OL6-00-000530'
  tag gtitle: 'SRG-OS-000368'
  tag fix_id: 'F-9326r358005_fix'
  tag 'documentable'
  tag legacy: ['V-81457', 'SV-96171']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end

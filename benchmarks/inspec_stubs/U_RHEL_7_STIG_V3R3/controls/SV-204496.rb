control 'SV-204496' do
  title 'The Red Hat Enterprise Linux operating system must use a separate file system for /tmp (or equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Verify that a separate file system/partition has been created for "/tmp".

Check that a file system/partition has been created for "/tmp" with the following command:

# systemctl is-enabled tmp.mount
enabled

If the "tmp.mount" service is not enabled, check to see if "/tmp" is defined in the fstab with a device and mount point:

# grep -i /tmp /etc/fstab
UUID=a411dc99-f2a1-4c87-9e05-184977be8539 /tmp   ext4   rw,relatime,discard,data=ordered,nosuid,noexec, 0 0

If "tmp.mount" service is not enabled or the "/tmp" directory is not defined in the fstab with a device and mount point, this is a finding.'
  desc 'fix', 'Start the "tmp.mount" service with the following command:

# systemctl enable tmp.mount
   
OR

Edit the "/etc/fstab" file and ensure the "/tmp" directory is defined in the fstab with a device and mount point.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-36346r602636_chk'
  tag severity: 'low'
  tag gid: 'V-204496'
  tag rid: 'SV-204496r603261_rule'
  tag stig_id: 'RHEL-07-021340'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-36309r602637_fix'
  tag 'documentable'
  tag legacy: ['SV-86689', 'V-72065']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

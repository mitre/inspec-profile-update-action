control 'SV-218023' do
  title 'The noexec option must be added to removable media partitions.'
  desc 'Allowing users to execute binaries from removable media such as USB keys exposes the system to potential compromise.'
  desc 'check', 'Identify any removable media that is configured on the system:

# cat /etc/fstab

/dev/mapper/vg_rhel6-lv_root /                       ext4    defaults        1 1
UUID=0be9b205-f8e6-4bf4-b0ba-1f235fc55936 /boot      ext4    defaults        1 2
UUID=5D49-30B2          /boot/efi               vfat    umask=0077,shortname=winnt 0 0
/dev/mapper/vg_rhel6-lv_home /home              ext4    defaults        1 2
/dev/mapper/vg_rhel6-lv_tmp /tmp                    ext4    defaults        1 2
/dev/mapper/vg_rhel6-lv_var /var                       ext4    defaults        1 2
/dev/mapper/vg_rhel6-lv_swap swap                 swap   defaults        0 0
tmpfs                 /dev/shm          tmpfs     defaults        0 0
devpts               /dev/pts            devpts    gid=5,mode=620  0 0
sysfs                   /sys                    sysfs       defaults        0 0
proc                    /proc                 proc       defaults        0 0
/dev/sdc1         /media/usb       vfat        defaults,rw,noexec 0 0

If any of the identified removable media devices do not have "noexec" defined, this is a finding.'
  desc 'fix', 'The "noexec" mount option prevents the direct execution of binaries on the mounted filesystem. Users should not be allowed to execute binaries that exist on partitions mounted from removable media (such as a USB key). The "noexec" option prevents code from being executed directly from the media itself, and may therefore provide a line of defense against certain types of worms or malicious code. Add the "noexec" option to the fourth column of "/etc/fstab" for the line which controls mounting of any removable media partitions.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19504r377084_chk'
  tag severity: 'low'
  tag gid: 'V-218023'
  tag rid: 'SV-218023r603264_rule'
  tag stig_id: 'RHEL-06-000271'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19502r377085_fix'
  tag 'documentable'
  tag legacy: ['SV-50456', 'V-38655']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

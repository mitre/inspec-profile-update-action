control 'SV-217178' do
  title 'SUSE operating system file systems that contain user home directories must be mounted to prevent files with the setuid and setgid bit set from being executed.'
  desc 'The "nosuid" mount option causes the system to not execute setuid and setgid files with owner privileges. This option must be used for mounting any file system not containing approved setuid and setguid files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', %q(Verify that SUSE operating system file systems that contain user home directories are mounted with the "nosuid" option.

Print the currently active file system mount options of the file system(s) that contain the user home directories with the following command:

# for X in `awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd`; do findmnt -nkT $X; done | sort -r
/home  /dev/mapper/system-home ext4   rw,nosuid,relatime,data=ordered

If a file system containing user home directories is not mounted with the FSTYPE OPTION nosuid, this is a finding.

Note: If a separate file system has not been created for the user home directories (user home directories are mounted under "/"), this is not a finding as the "nosuid" option cannot be used on the "/" system.)
  desc 'fix', 'Configure the SUSE operating system "/etc/fstab" file to use the "nosuid" option on file systems that contain user home directories for interactive users.

Re-mount the filesystems.

# mount -o remount /home'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18406r622354_chk'
  tag severity: 'medium'
  tag gid: 'V-217178'
  tag rid: 'SV-217178r603891_rule'
  tag stig_id: 'SLES-12-010790'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18404r369691_fix'
  tag 'documentable'
  tag legacy: ['SV-91925', 'V-77229']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-221741' do
  title 'The Oracle Linux operating system must be configured so that file systems containing user home directories are mounted to prevent files with the setuid and setgid bit set from being executed.'
  desc 'The "nosuid" mount option causes the system not to execute setuid and setgid files with owner privileges. This option must be used for mounting any file system not containing approved setuid and setguid files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', %q(Verify file systems that contain user home directories are mounted with the "nosuid" option.

Find the file system(s) that contain the user home directories with the following command:

Note: If a separate file system has not been created for the user home directories (user home directories are mounted under "/"), this is not a finding as the "nosuid" option cannot be used on the "/" system.

# awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd
smithj 1001 /home/smithj
thomasr 1002 /home/thomasr

Check the file systems mounted at boot time with the following command:

# more /etc/fstab

UUID=a411dc99-f2a1-4c87-9e05-184977be8539 /home ext4 rw,relatime,discard,data=ordered,nosuid 0 2

If a file system found in "/etc/fstab" refers to the user home directory file system and it does not have the "nosuid" option set, this is a finding.)
  desc 'fix', 'Configure the "/etc/fstab" to use the "nosuid" option on file systems that contain user home directories.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23456r622265_chk'
  tag severity: 'medium'
  tag gid: 'V-221741'
  tag rid: 'SV-221741r603801_rule'
  tag stig_id: 'OL07-00-021000'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23445r419296_fix'
  tag 'documentable'
  tag legacy: ['SV-108325', 'V-99221']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-216198' do
  title 'All valid SUID/SGID files must be documented.'
  desc 'There are valid reasons for SUID/SGID programs, but it is important to identify and review such programs to ensure they are legitimate.'
  desc 'check', 'The root role is required.

# find / \\( -fstype nfs -o -fstype cachefs -o -fstype autofs \\
-o -fstype ctfs -o -fstype mntfs -o -fstype objfs \\
-o -fstype proc \\) -prune -o -type f -perm -4000 -o \\
-perm -2000 -print

Output should only be Solaris-provided files and approved customer files.

Solaris-provided SUID/SGID files can be listed using the command: 

# pkg contents -a mode=4??? -a mode=2??? -t file -o pkg.name,path,mode

Digital signatures on the Solaris Set-UID binaries can be verified with the elfsign utility, such as this example:

# elfsign verify -e /usr/bin/su
elfsign: verification of /usr/bin/su passed.

This message indicates that the binary is properly signed.

If non-vendor provided or non-approved files are included in the list, this is a finding.'
  desc 'fix', 'The root role is required.

Determine the existence of any set-UID programs that do not belong on the system, and work with the owners (or system administrator) to determine the best course of action in accordance with site policy.'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17436r372976_chk'
  tag severity: 'low'
  tag gid: 'V-216198'
  tag rid: 'SV-216198r603268_rule'
  tag stig_id: 'SOL-11.1-070190'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17434r372977_fix'
  tag 'documentable'
  tag legacy: ['V-48059', 'SV-60931']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

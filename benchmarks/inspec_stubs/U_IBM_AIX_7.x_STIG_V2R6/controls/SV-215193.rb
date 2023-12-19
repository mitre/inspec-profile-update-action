control 'SV-215193' do
  title 'The AIX root account must not have world-writable directories in its executable search path.'
  desc "If the root search path contains a world-writable directory, malicious software could be placed in the path by intruders and/or malicious users and inadvertently run by root with all of root's privileges."
  desc 'check', %q(Check for world-writable permissions on all directories in the root user's executable search path:

# ls -ld `echo $PATH | sed "s/:/ /g"` 
drwxr-xr-x   33 root     system         8192 Nov 29 14:45 /etc
drwxr-xr-x    3 bin      bin             256 Aug 11 2017  /sbin
drwxr-xr-x    4 bin      bin           45056 Oct 31 12:59 /usr/bin
drwxr-xr-x    1 bin      bin             16 Aug 11 2017  /usr/bin/X11
drwxr-xr-x    2 bin      bin            4096 Aug 11 2017  /usr/java7_64/bin
drwxr-xr-x    4 bin      bin            4096 Feb 17 2017  /usr/java7_64/jre/bin
drwxr-xr-x    8 bin      bin           49152 Oct 31 12:59 /usr/sbin
drwxrwxr-x    2 bin      bin            4096 Aug 11 2017  /usr/ucb

If any of the directories in the "PATH" variable are world-writable, this is a finding.)
  desc 'fix', "For each world-writable path in root's executable search path, perform one of the following. 

Remove the world-writable permission on the directory. 

Run command: 
# chmod o-w <path> 

-OR-
Remove the world-writable directory from the executable search path. Identify and edit the initialization file referencing the world-writable directory and remove it from the PATH variable."
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16391r294030_chk'
  tag severity: 'medium'
  tag gid: 'V-215193'
  tag rid: 'SV-215193r508663_rule'
  tag stig_id: 'AIX7-00-001034'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16389r294031_fix'
  tag 'documentable'
  tag legacy: ['SV-101719', 'V-91621']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

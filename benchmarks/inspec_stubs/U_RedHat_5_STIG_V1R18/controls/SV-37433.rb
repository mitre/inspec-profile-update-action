control 'SV-37433' do
  title 'User start-up files must not execute world-writable programs.'
  desc 'If start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to become trojans that destroy user files or otherwise compromise the system at the user, or higher, level.  If the system is compromised at the user level, it is much easier to eventually compromise the system at the root and network level.'
  desc 'check', 'Determine the world writable files on the system (Note: ignore all files under /proc):

# find / -perm -002 -a -type f -exec ls -ld {} \\; | <more or redirect the output to a file>
 
# find / -perm -002 -a -type d -exec ls -ld {} \\; | <more or redirect the output to a file>

View the password file to determine where the home directories for users are: 

# more /etc/passwd

Once the directory for the human users is determined, grep for the lists of world writable files and directories within the users’ home directories.

An example would be:
# grep /opt/app/bin/daemon /home/*/.*  

where /home is the directory for the human users on the system and /opt/app/bin/daemon is a world writable file.'
  desc 'fix', 'Remove the world-writable permission of files referenced by local initialization scripts, or remove the references to these files in the local initialization scripts.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36012r7_chk'
  tag severity: 'medium'
  tag gid: 'V-4087'
  tag rid: 'SV-37433r3_rule'
  tag stig_id: 'GEN001940'
  tag gtitle: 'GEN001940'
  tag fix_id: 'F-31263r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

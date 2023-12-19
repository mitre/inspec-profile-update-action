control 'SV-45162' do
  title 'User start-up files must not execute world-writable programs.'
  desc 'If start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to become trojans that destroy user files or otherwise compromise the system at the user, or higher, level.  If the system is compromised at the user level, it is much easier to eventually compromise the system at the root and network level.'
  desc 'check', 'Check local initialization files for any executed world-writable programs or scripts and scripts executing from world writable directories.

Procedure:
For each home directory on the system make a list of files referenced within any local initialization script.
Show the mode for each file and its parent directory.

# FILES=".bashrc .bash_login .bash_logout .bash_profile .cshrc .kshrc .login .logout .profile .tcshrc .env .dtprofile .dispatch .emacs .exrc";

# for HOMEDIR in `cut -d: -f6 /etc/passwd|sort|uniq`;do for INIFILE in $FILES;do REFLIST=`egrep " [\\"~]?/" ${HOMEDIR}/${INIFILE} 2>/dev/null|sed "s/.*\\([~ \\"]\\/[\\.0-9A-Za-z_\\/\\-]*\\).*/\\1/"`;for REFFILE in $REFLIST;do FULLREF=`echo $REFFILE|sed "s:\\~:${HOMEDIR}:g"|sed "s:^\\s*::g"`;dirname $FULLREF|xargs stat -c "dir:%a:%n";stat -c "file:%:%n" $FULLREF;done;done;
done|sort|uniq

If any local initialization file executes a world-writable program or script or a script from a world-writable directory, this is a finding.'
  desc 'fix', 'Remove the world-writable permission of files referenced by local initialization scripts, or remove the references to these files in the local initialization scripts.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42506r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4087'
  tag rid: 'SV-45162r1_rule'
  tag stig_id: 'GEN001940'
  tag gtitle: 'GEN001940'
  tag fix_id: 'F-38559r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

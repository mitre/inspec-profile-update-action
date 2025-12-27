control 'SV-45014' do
  title 'All interactive user home directories defined in the /etc/passwd file must exist.'
  desc 'If a user has a home directory defined that does not exist, the user may be given the / directory, by default, as the current working directory upon logon.  This could create a Denial of Service because the user would not be able to perform useful tasks in this location.'
  desc 'check', "Use pwck to verify assigned home directories exist.
# pwck
If any user's assigned home directory does not exist, this is a finding."
  desc 'fix', 'If a user has no home directory, determine why. If possible, delete accounts without a home directory. If the account is valid, then create the home directory using the appropriate system administration utility or manually.
For example:
# /sbin/yast2 users
   (<select user> > Edit > Details)

  OR
# mkdir </home/directory>  
# for i in $(ls -A /etc/skel); do cp -rp /etc/skel/$i </home/directory>; done
# chown -R <user>:<group> </home/directory>
Document all changes.'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42410r1_chk'
  tag severity: 'low'
  tag gid: 'V-900'
  tag rid: 'SV-45014r1_rule'
  tag stig_id: 'GEN001460'
  tag gtitle: 'GEN001460'
  tag fix_id: 'F-38430r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

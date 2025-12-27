control 'SV-45092' do
  title 'System start-up files must only execute programs owned by a privileged UID or an application.'
  desc 'System start-up files executing programs owned by other than root (or another privileged user) or an application indicating the system may have been compromised.'
  desc 'check', %q(Determine the programs executed by system start-up files. Determine the ownership of the executed programs. 

# cat /etc/rc*/* /etc/init.d/* | more
# ls -l <executed program>

Alternatively:
# for FILE in `egrep -r "/" /etc/rc.* /etc/init.d|awk '/^.*[^\/][0-9A-Za-z_\/]*/{print $2}'|egrep "^/"|sort|uniq`;do if [ -e $FILE ]; then stat -L -c '%U:%n' $FILE;fi;done

This provides a list of files referenced by initialization scripts and their associated UIDs.
If any file is run by an initialization file and is not owned by root, sys, bin, or in rare cases, an application account, this is a finding.)
  desc 'fix', 'Change the ownership of the file executed from system startup scripts to root, bin, sys, or other.
# chown root <executed file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42453r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4091'
  tag rid: 'SV-45092r1_rule'
  tag stig_id: 'GEN001700'
  tag gtitle: 'GEN001700'
  tag fix_id: 'F-38495r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

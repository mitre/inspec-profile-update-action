control 'SV-220076' do
  title 'Graphical desktop environments provided by the system must automatically lock after 15 minutes of inactivity and the system must require users to re-authenticate to unlock the environment.'
  desc 'If graphical desktop sessions do not lock the session after 15 minutes of inactivity, requiring re-authentication to resume operations, the system or individual data could be compromised by an alert intruder who could exploit the oversight. This requirement applies to graphical desktop environments provided by the system to locally attached displays and input devices as well as to graphical desktop environments provided to remote systems, including thin clients.'
  desc 'check', "Examine the dtsession timeout variable setting:

# cat /etc/dt/config/C/sys.resources | grep -i dtsession | grep -i lockTimeout
If the dtsession timeout is greater than 15, commented or does not exist, this is a finding.

Examine the Open Windows timeout settings, both global and for every user.

# cat /usr/openwin/lib/app-defaults/XScreenSaver | egrep -i '\\*(lock|timeout):'
If the global Open Windows timeout is greater than 15 minutes, commented or does not exist, this is a finding.  If the global lock setting is not true, this is a finding.

# cut -d: -f6 /etc/passwd | xargs -iX egrep -i '^(lock|timeout):' X/.xscreensaver
If the Open Windows timeout is greater than 15 minutes for any user, this is a finding.  If the lock setting is not true for any user, this is a finding."
  desc 'fix', "Configure the CDE lock manager to lock your screen after a certain amount of inactive time. To configure the CDE lock manager to lock the screen after 15 minutes of inactive time, enter the following commands (be sure NOT to overwrite an existing file).
#
cp /usr/dt/config/C/sys.resources /etc/dt/config/C/sys.resources
# vi /etc/dt/config/C/sys.resources

Locate and add/uncomment/change the line to N=15.
dtsession*lockTimeout: <N>
dtsession*lockTimeout: 15

Log out of CDE and log back in to verify that the timeout is in effect.   

The timeout parameter in /usr/openwin/lib/app-defaults/XScreenSaver and all users' .xscreensaver files should also be confirmed to be uncommented and set to 0:15:00."
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36425r602878_chk'
  tag severity: 'medium'
  tag gid: 'V-220076'
  tag rid: 'SV-220076r603266_rule'
  tag stig_id: 'GEN000500'
  tag gtitle: 'SRG-OS-000029'
  tag fix_id: 'F-36389r602879_fix'
  tag 'documentable'
  tag legacy: ['V-4083', 'SV-39814']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end

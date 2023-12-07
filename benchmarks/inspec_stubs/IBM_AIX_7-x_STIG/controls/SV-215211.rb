control 'SV-215211' do
  title 'AIX must be configured to allow users to directly initiate a session lock for all connection types.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. Rather than be forced to wait for a period of time to expire before the user session can be locked, operating systems need to provide users with the ability to manually invoke a session lock so users may secure their session should the need arise for them to temporarily vacate the immediate physical vicinity.'
  desc 'check', 'Check if the "lock" command exists by using the following command:
# ls /usr/bin/lock

The above command should display the following:
/usr/bin/lock

If the above command does not show that "/usr/bin/lock" exists, this is a finding.

Check if the "xlock" command exists by using the following command:
# ls  /usr/bin/X11/xlock

The above command should display the following:
/usr/bin/X11/xlock

If the above command does not show that "/usr/bin/xlock" exists, this is a finding.'
  desc 'fix', 'Install, or re-install, bos.rte.security fileset from the AIX DVD Volume 1 using the following command (assuming that the DVD device is /dev/cd0):
# installp -aXYgd /dev/cd0 -e /tmp/install.log bos.rte.security'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16409r294084_chk'
  tag severity: 'medium'
  tag gid: 'V-215211'
  tag rid: 'SV-215211r508663_rule'
  tag stig_id: 'AIX7-00-001100'
  tag gtitle: 'SRG-OS-000030-GPOS-00011'
  tag fix_id: 'F-16407r294085_fix'
  tag 'documentable'
  tag legacy: ['V-91235', 'SV-101335']
  tag cci: ['CCI-000058']
  tag nist: ['AC-11 a']
end

control 'SV-215212' do
  title 'AIX CDE must conceal, via the session lock, information previously visible on the display with a publicly viewable image.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. The operating system session lock event must include an obfuscation of the display screen so as to prevent other users from reading what was previously displayed.

Publicly viewable images can include static or dynamic images, for example, patterns used with screen savers, photographic images, solid colors, a clock, a battery life indicator, or a blank screen, with the additional caveat that none of the images convey sensitive information.'
  desc 'check', 'If CDE (X11) is not used on AIX, this is Not Applicable.

Ensure that the screen saver and session timeout are not disabled.

From the command prompt, run the following script:

# AIX7-00-001101_Check.sh

Note: This script is included in the STIG package.

The above script should yield the following output:

Checking config file /etc/dt/config/C/sys.resources...
Missing config file /etc/dt/config/C/sys.resources

Checking config file /etc/dt/config/POSIX/sys.resources...
dtsession*saverTimeout: 15
dtsession*lockTimeout: 30

Checking config file /etc/dt/config/en_US/sys.resources...
dtsession*saverTimeout: 15
dtsession*lockTimeout: 25

If the result of the script shows any config file missing, or any of the "dtsession*saverTimeout" or "dtsession*lockTimeout" values is greater than "15", this is a finding.'
  desc 'fix', 'From the command prompt, run the following script to set the default timeout parameters "dtsession*saverTimeout:" and "dtsession*lockTimeout:" as "15" minutes: 

# AIX7-00-001101_Fix.sh

Note: This script is included in the STIG package.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16410r294087_chk'
  tag severity: 'medium'
  tag gid: 'V-215212'
  tag rid: 'SV-215212r508663_rule'
  tag stig_id: 'AIX7-00-001101'
  tag gtitle: 'SRG-OS-000031-GPOS-00012'
  tag fix_id: 'F-16408r294088_fix'
  tag 'documentable'
  tag legacy: ['SV-101337', 'V-91237']
  tag cci: ['CCI-000060']
  tag nist: ['AC-11 (1)']
end

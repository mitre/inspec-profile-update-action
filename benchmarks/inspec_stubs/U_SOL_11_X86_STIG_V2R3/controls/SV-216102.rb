control 'SV-216102' do
  title 'Graphical desktop environments provided by the system must automatically lock after 15 minutes of inactivity.'
  desc 'Allowing access to a graphical environment when the user is not attending the system can allow unauthorized users access to the system.'
  desc 'check', 'If the system is not running XWindows, this check does not apply.

Determine if the screen saver timeout is configured properly.

# grep "^\\*timeout:" /usr/share/X11/app-defaults/XScreenSaver

If the output is not:
*timeout: 0:15:00
this is a finding.

# grep "^\\*lockTimeout:" /usr/share/X11/app-defaults/XScreenSaver

If the output is not:
*lockTimeout: 0:00:05
this is a finding.

# grep "^\\*lock:" /usr/share/X11/app-defaults/XScreenSaver

If the output is not:
*lock: True
this is a finding.

For each existing user, check the configuration of their personal .xscreensaver file.
# grep "^lock:" $HOME/.xscreensaver

If the output is not:
*lock: True
this is a finding.

grep "^lockTimeout:" $HOME/.xscreensaver
If the output is not:
*lockTimeout: 0:00:05
this is a finding.'
  desc 'fix', 'The root role is required.

Edit the global screensaver configuration file to ensure 15 minute screen lock.

# pfedit /usr/share/X11/app-defaults/XScreenSaver

Find the timeout control lines and change them to read:

*timeout: 0:15:00
*lockTimeout:0:00:05
*lock: True

For each user on the system, edit their local $HOME/.xscreensaver file and change the timeout values.

# pfedit $HOME/.xscreensaver

Find the timeout control lines and change them to read:

timeout: 0:15:00
lockTimeout:0:00:05
lock: True'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17340r372688_chk'
  tag severity: 'medium'
  tag gid: 'V-216102'
  tag rid: 'SV-216102r603268_rule'
  tag stig_id: 'SOL-11.1-040180'
  tag gtitle: 'SRG-OS-000029'
  tag fix_id: 'F-17338r372689_fix'
  tag 'documentable'
  tag legacy: ['V-48047', 'SV-60919']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end

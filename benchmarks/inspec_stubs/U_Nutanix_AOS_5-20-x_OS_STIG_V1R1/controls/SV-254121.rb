control 'SV-254121' do
  title 'Nutanix AOS must disconnect a session after 15 minutes of idle time for all connection types.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined. The operating system session lock event must include an obfuscation of the display screen so as to prevent other users from reading what was previously displayed.

Publicly viewable images can include static or dynamic images, for example, patterns used with screen savers, photographic images, solid colors, a clock, a battery life indicator, or a blank screen, with the additional caveat that none of the images convey sensitive information.

'
  desc 'check', 'Confirm Nutanix AOS is configured for autologout after 15 minutes of idle time.

$ sudo grep -i tmout /etc/profile.d/*
/etc/profile.d/os-security.sh:readonly TMOUT=900

If "TMOUT" is not set to "900" or less in a script located in the /etc/profile.d/ directory to enforce session termination after inactivity, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS for autologout of idle sessions by running the following commands.

$ sudo salt-call state.sls security/CVM/shellCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57606r846449_chk'
  tag severity: 'medium'
  tag gid: 'V-254121'
  tag rid: 'SV-254121r846451_rule'
  tag stig_id: 'NUTX-OS-000020'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-57557r846450_fix'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000030-GPOS-00011', 'SRG-OS-000031-GPOS-00012']
  tag 'documentable'
  tag cci: ['CCI-000057', 'CCI-000058', 'CCI-000060']
  tag nist: ['AC-11 a', 'AC-11 a', 'AC-11 (1)']
end

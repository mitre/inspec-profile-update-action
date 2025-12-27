control 'SV-226453' do
  title 'The system must display a publicly-viewable pattern during a graphical desktop environment session lock.'
  desc 'To protect the on-screen content of a session, it must be replaced with a publicly-viewable pattern upon session lock. Examples of publicly viewable patterns include screen saver patterns, photographic images, solid colors, or a blank screen, so long as none of those patterns convey sensitive information.

This requirement applies to graphical desktop environments provided by the system to locally attached displays and input devices, as well as, to graphical desktop environments provided to remote systems using remote access protocols.'
  desc 'check', 'Determine if a publicly-viewable pattern is displayed during a session lock. If the session lock pattern is not publicly-viewable, this is a finding.

Acceptable checks for settings.

# grep -i dtsession /etc/dt/config/C/sys.resources | egrep -i "saverList|saverTimeout"

The saverTimeout value should be 15 (see GEN000500).
The saverList value of StartDtscreenBlank is an acceptable screensaver.'
  desc 'fix', 'Edit the /etc/dt/config/C/sys.resources file and add/edit the following lines, using 15 for the saverTimeout, and using StartDtscreenBlank for the saverList.

dtsession*saverTimeout:  15
dtsession*saverList: StartDtscreenBlank'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28614r482735_chk'
  tag severity: 'low'
  tag gid: 'V-226453'
  tag rid: 'SV-226453r603265_rule'
  tag stig_id: 'GEN000510'
  tag gtitle: 'SRG-OS-000029'
  tag fix_id: 'F-28602r482736_fix'
  tag 'documentable'
  tag legacy: ['V-22301', 'SV-39865']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end

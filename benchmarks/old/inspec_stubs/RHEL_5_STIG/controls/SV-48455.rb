control 'SV-48455' do
  title 'Graphical desktop environments provided by the system must automatically lock after 15 minutes of inactivity and the system must require users to re-authenticate to unlock the environment.

Applications requiring continuous, real-time screen display (i.e., network management products) require the following and need to be documented with the IAO.

-The logon session does not have administrator rights. 
-The display station (i.e., keyboard, monitor, etc.) is located in a controlled access area.'
  desc 'If graphical desktop sessions do not lock the session after 15 minutes of inactivity, requiring re-authentication to resume operations, the system or individual data could be compromised by an alert intruder who could exploit the oversight.  This requirement applies to graphical desktop environments provided by the system to locally attached displays and input devices as well as to graphical desktop environments provided to remote systems, including thin clients.'
  desc 'fix', 'For the Gnome screen saver, set the idle_activation_enabled flag.
Procedure:
# gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type bool --set /apps/gnome-screensaver/idle_activation_enabled true'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-4083'
  tag rid: 'SV-48455r1_rule'
  tag stig_id: 'GEN000500'
  tag gtitle: 'GEN000500'
  tag fix_id: 'F-26907r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end

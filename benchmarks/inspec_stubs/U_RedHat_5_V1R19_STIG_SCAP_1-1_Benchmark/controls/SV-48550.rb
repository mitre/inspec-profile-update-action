control 'SV-48550' do
  title 'The graphical desktop environment must set the idle timeout to no more than 15 minutes.'
  desc 'If graphical desktop sessions do not lock the session after 15 minutes of inactivity, requiring re-authentication to resume operations, the system or individual data could be compromised by an alert intruder who could exploit the oversight. This requirement applies to graphical desktop environments provided by the system to locally attached displays and input devices as well as to graphical desktop environments provided to remote systems, including thin clients.'
  desc 'fix', 'For the Gnome screen saver, set idle_delay to 15.

Procedure:
# gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --type int --set /apps/gnome-screensaver/idle_delay 15'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-27283'
  tag rid: 'SV-48550r1_rule'
  tag stig_id: 'GEN000500-2'
  tag gtitle: 'GEN000500-2'
  tag fix_id: 'F-33041r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end

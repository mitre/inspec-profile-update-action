control 'SV-39096' do
  title 'Graphical desktop environments provided by the system must automatically lock after 15 minutes of inactivity and the system must require users to re-authenticate to unlock the environment.'
  desc 'If graphical desktop sessions do not lock the session after 15 minutes of inactivity, requiring re-authentication to resume operations, the system or individual data could be compromised by an alert intruder who could exploit the oversight. This requirement applies to graphical desktop environments provided by the system to locally attached displays and input devices, as well as, to graphical desktop environments provided to remote systems, including thin clients.'
  desc 'check', 'Log into a graphical desktop environment provided by the system. Allow the session to remain idle for 15 minutes. If the desktop session is not automatically locked after 15 minutes, or does not require re-authentication to resume operations, this is a finding.'
  desc 'fix', 'Consult vendor documentation to determine the settings required for the system to lock graphical desktop environments. Configure the system to lock graphical desktop environments after 15 minutes of inactivity and require re-authentication to resume operations.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-8205r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4083'
  tag rid: 'SV-39096r1_rule'
  tag stig_id: 'GEN000500'
  tag gtitle: 'GEN000500'
  tag fix_id: 'F-4016r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'PESL-1'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end

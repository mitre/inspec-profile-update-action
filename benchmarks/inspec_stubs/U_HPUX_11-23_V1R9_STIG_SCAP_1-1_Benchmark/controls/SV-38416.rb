control 'SV-38416' do
  title 'Graphical desktop environments provided by the system must automatically lock after 15 minutes of inactivity and must require users to re-authenticate to unlock the environment.'
  desc 'If graphical desktop sessions do not lock the session after 15 minutes of inactivity, requiring re-authentication to resume operations, the system or individual data could be compromised by an alert intruder who could exploit the oversight. This requirement applies to graphical desktop environments provided by the system to locally attached displays and input devices as well as to graphical desktop environments provided to remote systems, including thin clients.'
  desc 'fix', 'Configure the CDE lock manager to lock your screen after a certain amount of inactive time. To configure the CDE lock manager to lock the screen after 15 minutes of inactive time, enter the following commands (ensure to NOT overwrite an existing file):

# cp /usr/dt/config/C/sys.resources /etc/dt/config/C/sys.resources
# vi /etc/dt/config/C/sys.resources

Locate and add/uncomment/change the line to N=15
dtsession*lockTimeout: <N>
dtsession*lockTimeout: 15

Log out of CDE and log back in to verify the timeout is in effect.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-4083'
  tag rid: 'SV-38416r1_rule'
  tag stig_id: 'GEN000500'
  tag gtitle: 'GEN000500'
  tag fix_id: 'F-31513r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'PESL-1'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end

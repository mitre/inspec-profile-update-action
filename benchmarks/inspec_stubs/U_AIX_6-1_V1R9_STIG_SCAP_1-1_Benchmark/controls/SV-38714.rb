control 'SV-38714' do
  title 'The system must not have the talk or ntalk services active.'
  desc 'The talk and ntalk commands allow users on the same or different systems on converse. The talk daemons are started from the inetd process and run as root.  These unnecessary processes increase the attack vector of the system  and may cause Denial of Service by scrambling the users display.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out TCP and UDP for the talk service.   
Edit /etc/inetd.conf and comment out TCP and UDP for the ntalk service.

Restart the inetd service.   
# refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-29510'
  tag rid: 'SV-38714r1_rule'
  tag stig_id: 'GEN009260'
  tag gtitle: 'GEN009260'
  tag fix_id: 'F-33068r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end

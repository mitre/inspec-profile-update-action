control 'SV-27440' do
  title 'The system must not have the finger service active.'
  desc "The finger service provides information about the system's users to network clients.  This information could expose information that could be used in subsequent attacks."
  desc 'fix', 'Edit /etc/inetd.conf and comment out the finger service line.  Restart the inetd service.'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag severity: 'low'
  tag gid: 'V-4701'
  tag rid: 'SV-27440r1_rule'
  tag stig_id: 'GEN003860'
  tag gtitle: 'GEN003860'
  tag fix_id: 'F-24712r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end

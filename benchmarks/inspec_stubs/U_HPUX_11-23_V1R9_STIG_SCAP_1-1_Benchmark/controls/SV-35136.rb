control 'SV-35136' do
  title 'The system must not have the finger service active.'
  desc "The finger service provides information about the system's users to network clients. This could expose information that could be used in subsequent attacks."
  desc 'fix', 'Edit /etc/inetd.conf and comment out the fingerd line. Restart the inetd service via the following command:
# inetd -c'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'low'
  tag gid: 'V-4701'
  tag rid: 'SV-35136r1_rule'
  tag stig_id: 'GEN003860'
  tag gtitle: 'GEN003860'
  tag fix_id: 'F-30288r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'EBRU-1, DCPP-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end

control 'SV-38880' do
  title 'Network analysis tools must not be installed.'
  desc 'Network analysis tools allow for the capture of network traffic visible to the system.'
  desc 'fix', 'Remove the network analysis tool binary from the system. 

Procedure:
# rm /usr/sbin/tcpdump'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-12049'
  tag rid: 'SV-38880r1_rule'
  tag stig_id: 'GEN003865'
  tag gtitle: 'GEN003865'
  tag fix_id: 'F-33131r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPA-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end

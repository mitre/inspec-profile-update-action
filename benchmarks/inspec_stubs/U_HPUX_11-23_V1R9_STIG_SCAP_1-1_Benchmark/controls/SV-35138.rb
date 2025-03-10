control 'SV-35138' do
  title 'Network analysis tools must not be installed.'
  desc 'Network analysis tools allow for the capture of network traffic visible to the system.'
  desc 'fix', 'Remove the network analysis tool binary from the system. Consult vendor documentation for removing packaged software, or remove the binary directly via the following example:
# rm -i <binary>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-12049'
  tag rid: 'SV-35138r1_rule'
  tag stig_id: 'GEN003865'
  tag gtitle: 'GEN003865'
  tag fix_id: 'F-31909r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPA-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end

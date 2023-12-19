control 'SV-35074' do
  title 'The xinetd.d directory must have mode 0755 or less permissive.'
  desc 'The Internet service daemon configuration files must be protected as malicious modification could cause Denial of Service or increase the attack surface of the system.'
  desc 'fix', 'Change the mode of included xinetd configuration 
directories to 0755.
# chmod 0755 <directory>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22425'
  tag rid: 'SV-35074r1_rule'
  tag stig_id: 'GEN003750'
  tag gtitle: 'GEN003750'
  tag fix_id: 'F-31888r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end

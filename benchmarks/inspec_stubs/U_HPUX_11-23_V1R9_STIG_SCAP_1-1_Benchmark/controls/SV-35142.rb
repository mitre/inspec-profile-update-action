control 'SV-35142' do
  title 'The SSH daemon must not allow rhosts RSA authentication.'
  desc 'If SSH permits rhosts RSA authentication, a user may be able to login based on the keys of the host originating the request and not any user-specific authentication..'
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the RhostsRSAAuthentication setting value to no.   

Note that the above guidance applies exclusively to Protocol(s) 1/1,2/2,1 only. If using Protocol 2 only, the check is not applicable and further action is not required.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22487'
  tag rid: 'SV-35142r1_rule'
  tag stig_id: 'GEN005538'
  tag gtitle: 'GEN005538'
  tag fix_id: 'F-30293r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

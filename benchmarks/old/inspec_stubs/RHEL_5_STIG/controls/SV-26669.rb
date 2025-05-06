control 'SV-26669' do
  title 'The rlogind service must not be installed.'
  desc 'The rlogind process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'fix', 'Remove the rsh-server package.

Procedure:
# rpm -e rsh-server'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22433'
  tag rid: 'SV-26669r1_rule'
  tag stig_id: 'GEN003835'
  tag gtitle: 'GEN003835'
  tag fix_id: 'F-23909r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end

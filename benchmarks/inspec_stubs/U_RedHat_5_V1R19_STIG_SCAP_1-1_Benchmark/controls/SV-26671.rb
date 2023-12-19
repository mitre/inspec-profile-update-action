control 'SV-26671' do
  title 'The rlogind service must not be running.'
  desc 'The rlogind process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'fix', 'Remove or disable the rlogin configuration and restart xinetd.
# rm /etc/xinetd.d/rlogin ; service xinetd restart'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22432'
  tag rid: 'SV-26671r1_rule'
  tag stig_id: 'GEN003830'
  tag gtitle: 'GEN003830'
  tag fix_id: 'F-23912r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

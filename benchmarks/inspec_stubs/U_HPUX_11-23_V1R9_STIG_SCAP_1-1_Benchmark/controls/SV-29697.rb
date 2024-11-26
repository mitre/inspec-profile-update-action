control 'SV-29697' do
  title 'The rlogind service must not be running.'
  desc 'The rlogind process provides a typically unencrypted, host-authenticated remote access service. SSH should be used in place of this service.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out the rlogind service. Restart the inetd service via the following command:
# inetd -c'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22432'
  tag rid: 'SV-29697r1_rule'
  tag stig_id: 'GEN003830'
  tag gtitle: 'GEN003830'
  tag fix_id: 'F-31902r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

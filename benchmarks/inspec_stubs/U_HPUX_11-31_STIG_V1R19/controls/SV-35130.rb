control 'SV-35130' do
  title 'The remsh daemon must not be running.'
  desc 'The remshd process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', '# cat /etc/inetd.conf | grep -v "^#" | grep -c remshd

If the above command return value is greater than 0, this is a finding.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out the remshd service. 

Refresh the inetd service.
# inetd -c'
  impact 0.7
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-34988r1_chk'
  tag severity: 'high'
  tag gid: 'V-4687'
  tag rid: 'SV-35130r1_rule'
  tag stig_id: 'GEN003820'
  tag gtitle: 'GEN003820'
  tag fix_id: 'F-30282r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'EBRU-1'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

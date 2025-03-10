control 'SV-27434' do
  title 'The rsh daemon must not be running.'
  desc 'The rshd process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', '# grep -v "^#" /etc/inetd.conf |grep rshd
If rshd is found to be enabled, this is a finding.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out the rshd service.  Restart the inetd service.'
  impact 0.7
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28620r1_chk'
  tag severity: 'high'
  tag gid: 'V-4687'
  tag rid: 'SV-27434r1_rule'
  tag stig_id: 'GEN003820'
  tag gtitle: 'GEN003820'
  tag fix_id: 'F-24706r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'EBRU-1'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

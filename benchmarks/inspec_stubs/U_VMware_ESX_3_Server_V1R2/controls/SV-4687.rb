control 'SV-4687' do
  title 'The rsh daemon must not be running.'
  desc 'The rshd process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', 'Verify the rshd service is not running.'
  desc 'fix', 'Disable the rshd service.'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16169r2_chk'
  tag severity: 'high'
  tag gid: 'V-4687'
  tag rid: 'SV-4687r2_rule'
  tag stig_id: 'GEN003820'
  tag gtitle: 'GEN003820'
  tag fix_id: 'F-4615r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'EBRU-1'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

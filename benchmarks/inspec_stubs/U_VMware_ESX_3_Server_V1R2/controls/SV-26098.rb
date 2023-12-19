control 'SV-26098' do
  title 'The rlogind service must not be running.'
  desc 'The rlogind process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', 'Determine if the rlogind service is running.  If it is, this is a finding.'
  desc 'fix', 'Disable the rlogind service.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29264r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22432'
  tag rid: 'SV-26098r1_rule'
  tag stig_id: 'GEN003830'
  tag gtitle: 'GEN003830'
  tag fix_id: 'F-26282r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

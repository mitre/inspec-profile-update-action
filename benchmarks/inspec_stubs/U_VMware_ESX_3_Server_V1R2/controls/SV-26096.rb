control 'SV-26096' do
  title 'The rshd service must not be installed.'
  desc 'The rshd process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', 'Determine if the rshd service is installed.  If so, this is a finding.'
  desc 'fix', 'Uninstall the rshd service from the system.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29263r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22431'
  tag rid: 'SV-26096r1_rule'
  tag stig_id: 'GEN003825'
  tag gtitle: 'GEN003825'
  tag fix_id: 'F-26281r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCPP-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end

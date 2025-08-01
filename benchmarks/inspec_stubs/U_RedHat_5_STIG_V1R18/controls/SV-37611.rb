control 'SV-37611' do
  title 'The system must not have Teredo enabled.'
  desc 'Teredo is an IPv6 transition mechanism involving tunneling IPv6 packets encapsulated in IPv4 packets. Unauthorized tunneling may circumvent network security.'
  desc 'check', 'Verify the Miredo service is not running.
# ps ax | grep miredo | grep -v grep
If the miredo process is running, this is a finding.'
  desc 'fix', 'Edit startup scripts to prevent the service from running on startup.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36805r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22546'
  tag rid: 'SV-37611r1_rule'
  tag stig_id: 'GEN007800'
  tag gtitle: 'GEN007800'
  tag fix_id: 'F-31647r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end

control 'SV-218683' do
  title 'The system must not have Teredo enabled.'
  desc 'Teredo is an IPv6 transition mechanism involving tunneling IPv6 packets encapsulated in IPv4 packets. Unauthorized tunneling may circumvent network security.'
  desc 'check', 'Verify the Miredo service is not running.
# ps ax | grep miredo | grep -v grep
If the miredo process is running, this is a finding.'
  desc 'fix', 'Edit startup scripts to prevent the service from running on startup.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20158r562930_chk'
  tag severity: 'medium'
  tag gid: 'V-218683'
  tag rid: 'SV-218683r603259_rule'
  tag stig_id: 'GEN007800'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-20156r562931_fix'
  tag 'documentable'
  tag legacy: ['V-22546', 'SV-63417']
  tag cci: ['CCI-000381', 'CCI-001551']
  tag nist: ['CM-7 a', 'AC-4']
end

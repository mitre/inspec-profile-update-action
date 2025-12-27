control 'SV-26224' do
  title 'The DHCP client must not send dynamic DNS updates.'
  desc 'Dynamic DNS updates transmit unencrypted information about a system including its name and address and should not be used unless needed.'
  desc 'check', "Determine if the system's DHCP client is configured to send dynamic DNS updates.  If it is, this is a finding."
  desc 'fix', "Configure the system's DHCP client to not send dynamic DNS updates."
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29305r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22549'
  tag rid: 'SV-26224r1_rule'
  tag stig_id: 'GEN007850'
  tag gtitle: 'GEN007850'
  tag fix_id: 'F-26337r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

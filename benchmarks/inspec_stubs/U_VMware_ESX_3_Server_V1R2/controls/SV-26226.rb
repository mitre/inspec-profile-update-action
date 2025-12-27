control 'SV-26226' do
  title 'The system must not send IPv6 ICMP redirects.'
  desc "ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table that could reveal portions of the network topology."
  desc 'check', 'Determine if the system is configured to send IPv6 ICMP redirects.  If it is, this is a finding.'
  desc 'fix', 'Configure the system to not send IPv6 ICMP redirects.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29307r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22551'
  tag rid: 'SV-26226r1_rule'
  tag stig_id: 'GEN007880'
  tag gtitle: 'GEN007880'
  tag fix_id: 'F-26339r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end

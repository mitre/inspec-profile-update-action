control 'SV-207227' do
  title 'The VPN Gateway must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  desc 'Failure to a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. VPN gateways that fail suddenly and with no incorporated failure state planning may leave the hosting system available but with a reduced security protection capability. Preserving information system state information also facilitates system restart and return to the operational mode of the organization with less disruption to mission-essential processes.

Abort refers to stopping a program or function before it has finished naturally. The term abort refers to both requested and unexpected terminations.'
  desc 'check', 'Verify the VPN Gateway is configured to fail to a secure state if system initialization fails, shutdown fails, or aborts fail.

If the VPN Gateway does not fail to a secure state if system initialization fails, shutdown fails, or aborts fail, this is a finding.'
  desc 'fix', 'Configure the VPN Gateway to fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7487r378302_chk'
  tag severity: 'medium'
  tag gid: 'V-207227'
  tag rid: 'SV-207227r608988_rule'
  tag stig_id: 'SRG-NET-000235-VPN-000820'
  tag gtitle: 'SRG-NET-000235'
  tag fix_id: 'F-7487r378303_fix'
  tag 'documentable'
  tag legacy: ['V-97133', 'SV-106271']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end

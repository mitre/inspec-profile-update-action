control 'SV-71129' do
  title 'The operating system must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  desc 'Failure to a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. Operating systems that fail suddenly and with no incorporated failure state planning may leave the system available but with a reduced security protection capability. Preserving operating system state information also facilitates system restart and return to the operational mode of the organization with less disruption to mission-essential processes. 

Abort refers to stopping a program or function before it has finished naturally. The term abort refers to both requested and unexpected terminations.'
  desc 'check', 'Verify the operating system fails to a secure state if system initialization fails, shutdown fails, or aborts fail. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57439r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56869'
  tag rid: 'SV-71129r1_rule'
  tag stig_id: 'SRG-OS-000184-GPOS-00078'
  tag gtitle: 'SRG-OS-000184-GPOS-00078'
  tag fix_id: 'F-61765r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end

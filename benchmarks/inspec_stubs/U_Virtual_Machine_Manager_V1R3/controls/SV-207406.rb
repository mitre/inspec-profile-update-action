control 'SV-207406' do
  title 'The VMM must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  desc 'Failure to a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. VMMs that fail suddenly and with no incorporated failure state planning may leave the system available but with a reduced security protection capability. Preserving VMM state information also facilitates system restart and return to the operational mode of the organization with less disruption to mission-essential processes.

Abort refers to stopping a program or function before it has finished naturally. The term abort refers to both requested and unexpected terminations.'
  desc 'check', 'Verify the VMM fails to a secure state if system initialization fails, shutdown fails, or aborts fail.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7663r365628_chk'
  tag severity: 'medium'
  tag gid: 'V-207406'
  tag rid: 'SV-207406r379081_rule'
  tag stig_id: 'SRG-OS-000184-VMM-000710'
  tag gtitle: 'SRG-OS-000184'
  tag fix_id: 'F-7663r365629_fix'
  tag 'documentable'
  tag legacy: ['V-57013', 'SV-71273']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end

control 'SV-207464' do
  title 'The VMM must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 

Synchronizing internal VMM clocks provides uniformity of time stamps for VMMs with multiple system clocks and systems connected over a network.'
  desc 'check', 'Verify the VMM synchronizes internal information system clocks to the authoritative time source when the time difference is greater than one second.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7721r365796_chk'
  tag severity: 'medium'
  tag gid: 'V-207464'
  tag rid: 'SV-207464r854637_rule'
  tag stig_id: 'SRG-OS-000356-VMM-001340'
  tag gtitle: 'SRG-OS-000356'
  tag fix_id: 'F-7721r365797_fix'
  tag 'documentable'
  tag legacy: ['SV-71389', 'V-57129']
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end

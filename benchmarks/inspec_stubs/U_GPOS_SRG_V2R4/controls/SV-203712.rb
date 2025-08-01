control 'SV-203712' do
  title 'The operating system must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations should consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems).

Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in SRG-OS-000355 because a comparison must be done in order to determine the time difference.'
  desc 'check', 'Verify the operating system synchronizes internal information system clocks to the authoritative time source when the time difference is greater than one second. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to synchronize internal information system clocks to the authoritative time source when the time difference is greater than the organization-defined time period.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3837r375143_chk'
  tag severity: 'medium'
  tag gid: 'V-203712'
  tag rid: 'SV-203712r379735_rule'
  tag stig_id: 'SRG-OS-000356-GPOS-00144'
  tag gtitle: 'SRG-OS-000356'
  tag fix_id: 'F-3837r375144_fix'
  tag 'documentable'
  tag legacy: ['V-57203', 'SV-71463']
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end

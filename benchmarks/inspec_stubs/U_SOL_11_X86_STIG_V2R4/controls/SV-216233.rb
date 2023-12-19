control 'SV-216233' do
  title 'The operating system must back up audit records at least every seven days onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up audit records to a different system or onto separate media than the system being audited on an organizationally defined frequency helps to assure in the event of a catastrophic system failure, the audit records will be retained.

This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.

This requirement can be met by the operating system continuously sending records to a centralized logging server.'
  desc 'check', 'This check applies to the global zone only. Determine the zone that you a currently securing.

# zonename

If the command output is "global" this check applies.

The operator must back up audit records at least every 7 days.

If the operator is unable to provide a documented procedure or the documented procedure is not being followed, then this is a finding.'
  desc 'fix', 'This fix applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

The operator shall back up audit records at least every seven days.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17471r373078_chk'
  tag severity: 'medium'
  tag gid: 'V-216233'
  tag rid: 'SV-216233r603268_rule'
  tag stig_id: 'SOL-11.1-090220'
  tag gtitle: 'SRG-OS-000215'
  tag fix_id: 'F-17469r373079_fix'
  tag 'documentable'
  tag legacy: ['V-47941', 'SV-60813']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end

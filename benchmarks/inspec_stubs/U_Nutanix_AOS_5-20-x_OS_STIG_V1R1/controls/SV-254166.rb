control 'SV-254166' do
  title 'Nutanix AOS must produce audit records containing information to establish where events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

To compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as operating system components, modules, device identifiers, node names, file names, and functionality.

Associating information about where the event occurred within the operating system provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.'
  desc 'check', 'Verify the operating system produces audit records containing information to establish when (date and time) the events occurred.

Determine if auditing is active by issuing the following command:

$ sudo systemctl is-active auditd.service
active

If the "auditd" status is not active, this is a finding.'
  desc 'fix', 'Enable the auditd service to run automatically.

$ sudo systemctl enable auditd'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57651r846584_chk'
  tag severity: 'medium'
  tag gid: 'V-254166'
  tag rid: 'SV-254166r846586_rule'
  tag stig_id: 'NUTX-OS-000640'
  tag gtitle: 'SRG-OS-000039-GPOS-00017'
  tag fix_id: 'F-57602r846585_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end

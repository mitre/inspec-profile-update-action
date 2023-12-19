control 'SV-254165' do
  title 'Nutanix AOS must produce audit records containing information to establish when events occurred.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

To compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know when events occurred (date and time).

Associating event types with detected events in the operating system audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.'
  desc 'check', 'Verify the operating system produces audit records containing information to establish when (date and time) the events occurred.

Determine if auditing is active by issuing the following command:

$ sudo systemctl is-active auditd.service
active

If the "auditd" status is not active, this is a finding.'
  desc 'fix', 'Enable the auditd service to run automatically.

$ sudo systemctl enable auditd'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57650r846581_chk'
  tag severity: 'medium'
  tag gid: 'V-254165'
  tag rid: 'SV-254165r846583_rule'
  tag stig_id: 'NUTX-OS-000630'
  tag gtitle: 'SRG-OS-000038-GPOS-00016'
  tag fix_id: 'F-57601r846582_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end

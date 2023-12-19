control 'SV-254167' do
  title 'Nutanix AOS must produce audit records containing information to establish the source of events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In addition to logging where events occur within the operating system, the operating system must also generate audit records that identify sources of events. Sources of operating system events include, but are not limited to, processes, and services.

To compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the source of the event.'
  desc 'check', 'Verify the operating system produces audit records containing information to establish when (date and time) the events occurred.

Determine if auditing is active by issuing the following command:

$ sudo systemctl is-active auditd.service
active

If the "auditd" status is not active, this is a finding.'
  desc 'fix', 'Enable the auditd service to run automatically.

$ sudo systemctl enable auditd'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57652r846587_chk'
  tag severity: 'medium'
  tag gid: 'V-254167'
  tag rid: 'SV-254167r846589_rule'
  tag stig_id: 'NUTX-OS-000650'
  tag gtitle: 'SRG-OS-000040-GPOS-00018'
  tag fix_id: 'F-57603r846588_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end

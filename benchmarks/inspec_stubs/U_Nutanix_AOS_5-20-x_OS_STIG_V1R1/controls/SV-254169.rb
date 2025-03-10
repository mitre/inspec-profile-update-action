control 'SV-254169' do
  title 'Nutanix AOS must produce audit records containing information to establish the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.'
  desc 'check', 'Confirm Nutanix AOS produces audit records containing information to establish when (date and time) the events occurred.

Determine if auditing is active by issuing the following command:

$ sudo systemctl is-active auditd.service
active

If the "auditd" status is not active, this is a finding.'
  desc 'fix', 'Configure the audit service to be active and start automatically with the system at startup. The Audit service is protected and restricted to allow access or modifications only from the root account.

$ sudo su -
# systemctl start auditd.service'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57654r846593_chk'
  tag severity: 'medium'
  tag gid: 'V-254169'
  tag rid: 'SV-254169r846595_rule'
  tag stig_id: 'NUTX-OS-000670'
  tag gtitle: 'SRG-OS-000255-GPOS-00096'
  tag fix_id: 'F-57605r846594_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end

control 'SV-254168' do
  title 'Nutanix AOS must produce audit records containing information to establish the outcome of events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'Verify the operating system produces audit records containing information to establish when (date and time) the events occurred.

Determine if auditing is active by issuing the following command:

$ sudo systemctl is-active auditd.service
active

If the "auditd" status is not active, this is a finding.'
  desc 'fix', 'Enable the auditd service to run automatically.

$ sudo systemctl enable auditd'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57653r846590_chk'
  tag severity: 'medium'
  tag gid: 'V-254168'
  tag rid: 'SV-254168r846592_rule'
  tag stig_id: 'NUTX-OS-000660'
  tag gtitle: 'SRG-OS-000041-GPOS-00019'
  tag fix_id: 'F-57604r846591_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end

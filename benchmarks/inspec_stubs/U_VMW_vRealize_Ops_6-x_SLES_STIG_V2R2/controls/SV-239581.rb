control 'SV-239581' do
  title 'The SLES for vRealize must produce audit records containing information to establish the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.'
  desc 'check', 'Verify SLES for vRealize produces audit records by running the following command to determine the current status of the "auditd" service:

# service auditd status

If the service is enabled, the returned message must contain the following text:

Checking for service auditd                running

If the service is not running, this is a finding.'
  desc 'fix', 'Enable the "auditd" service by performing the following commands:

# chkconfig auditd on
# service auditd start'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42814r662192_chk'
  tag severity: 'medium'
  tag gid: 'V-239581'
  tag rid: 'SV-239581r662194_rule'
  tag stig_id: 'VROM-SL-000875'
  tag gtitle: 'SRG-OS-000255-GPOS-00096'
  tag fix_id: 'F-42773r662193_fix'
  tag 'documentable'
  tag legacy: ['SV-99283', 'V-88633']
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end

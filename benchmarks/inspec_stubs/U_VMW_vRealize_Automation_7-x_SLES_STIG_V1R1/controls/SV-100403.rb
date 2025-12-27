control 'SV-100403' do
  title 'The SLES for vRealize must produce audit records containing information to establish the identity of any individual or process associated with the event.'
  desc 'Without information that establishes the identity of the subjects (i.e., users or processes acting on behalf of users) associated with the events, security personnel cannot determine responsibility for the potentially harmful event.'
  desc 'check', 'Verify the SLES for vRealize produces audit records by running the following command to determine the current status of the "auditd" service:

# service auditd status

If the service is enabled, the returned message must contain the following text:

Checking for service auditd                running

If the service is not "running", this is a finding.'
  desc 'fix', 'Enable the "auditd" service by performing the following commands:

# chkconfig auditd on
# service auditd start'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89445r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89753'
  tag rid: 'SV-100403r1_rule'
  tag stig_id: 'VRAU-SL-000900'
  tag gtitle: 'SRG-OS-000255-GPOS-00096'
  tag fix_id: 'F-96495r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end

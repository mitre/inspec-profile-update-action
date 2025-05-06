control 'SV-239453' do
  title 'The SLES for vRealize must produce audit records.'
  desc 'Without establishing what type of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the SLES for vRealize audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.'
  desc 'check', 'Verify SLES for vRealize produces audit records by running the following command to determine the current status of the "auditd" service:

# service auditd status

If the service is enabled, the returned message must contain the following text:

Checking for: 

service   auditd   running

If the service is not running, this is a finding.'
  desc 'fix', 'Enable the "auditd" service by performing the following commands:

# chkconfig auditd on
# service auditd start'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42686r661808_chk'
  tag severity: 'medium'
  tag gid: 'V-239453'
  tag rid: 'SV-239453r661810_rule'
  tag stig_id: 'VROM-SL-000085'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-42645r661809_fix'
  tag 'documentable'
  tag legacy: ['SV-99027', 'V-88377']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end

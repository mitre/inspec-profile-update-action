control 'SV-252973' do
  title 'TOSS audit records must contain information to establish what type of events occurred, when the events occurred, the source of events, where events occurred, and the outcome of events.'
  desc 'Without establishing what type of events occurred, when events occurred, the source of events, where events occurred, and the outcome of events, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in TOSS audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured TOSS system.

'
  desc 'check', 'Verify the audit service is configured to produce audit records.

Check that the audit service is installed properly with the following command:

$ sudo yum list installed audit

If the "audit" package is not installed, this is a finding.

Check that the audit service is properly running and active on the system with the following command:

$ sudo systemctl is-active auditd.service
active

If the command above returns "inactive", this is a finding.'
  desc 'fix', 'Configure the audit service to produce audit records containing the information needed to establish when (date and time) an event occurred.

Install the audit service (if the audit service is not already installed) with the following command:

$ sudo yum install audit

Enable the audit service with the following command:

$ sudo systemctl enable auditd.service

Start the audit service with the following command:

$ sudo systemctl start auditd.service'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56426r824241_chk'
  tag severity: 'medium'
  tag gid: 'V-252973'
  tag rid: 'SV-252973r824243_rule'
  tag stig_id: 'TOSS-04-030010'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-56376r824242_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000047-GPOS-00023', 'SRG-OS-000051-GPOS-00024', 'SRG-OS-000064-GPOS-00033', 'SRG-OS-000241-GPOS-00091', 'SRG-OS-000254-GPOS-00095', 'SRG-OS-000327-GPOS-00127', 'SRG-OS-000342-GPOS-00133', 'SRG-OS-000348-GPOS-00136', 'SRG-OS-000349-GPOS-00137', 'SRG-OS-000350-GPOS-00138', 'SRG-OS-000351-GPOS-00139', 'SRG-OS-000353-GPOS-00141', 'SRG-OS-000354-GPOS-00142', 'SRG-OS-000365-GPOS-00152', 'SRG-OS-000474-GPOS-00219', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000140', 'CCI-000154', 'CCI-000172', 'CCI-001405', 'CCI-001464', 'CCI-001814', 'CCI-001851', 'CCI-001875', 'CCI-001877', 'CCI-001878', 'CCI-001879', 'CCI-001881', 'CCI-001882', 'CCI-002234']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-5 b', 'AU-6 (4)', 'AU-12 c', 'AC-2 (4)', 'AU-14 (1)', 'CM-5 (1)', 'AU-4 (1)', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 b', 'AU-7 b', 'AC-6 (9)']
end

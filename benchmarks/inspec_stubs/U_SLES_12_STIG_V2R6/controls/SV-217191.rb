control 'SV-217191' do
  title 'SUSE operating system audit records must contain information to establish what type of events occurred, the source of events, where events occurred, and the outcome of events.'
  desc 'Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the SUSE operating system audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured SUSE operating system.

'
  desc 'check', 'Verify the SUSE operating system produces audit records.

Check that the SUSE operating system produces audit records by running the following command to determine the current status of the auditd service:

# systemctl status auditd.service

If the service is enabled, the returned message must contain the following text:

Active: active (running)

If the service is not running, this is a finding.'
  desc 'fix', 'Enable the SUSE operating system auditd service by performing the following commands:

# sudo systemctl enable auditd.service
# sudo systemctl start auditd.service'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18419r369729_chk'
  tag severity: 'medium'
  tag gid: 'V-217191'
  tag rid: 'SV-217191r603262_rule'
  tag stig_id: 'SLES-12-020010'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-18417r369730_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000051-GPOS-00024', 'SRG-OS-000054-GPOS-00025', 'SRG-OS-000122-GPOS-00063', 'SRG-OS-000254-GPOS-00095', 'SRG-OS-000255-GPOS-00096', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag legacy: ['V-77289', 'SV-91985']
  tag cci: ['CCI-000366', 'CCI-001464', 'CCI-001487', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000154', 'CCI-000158', 'CCI-001876', 'CCI-002884']
  tag nist: ['CM-6 b', 'AU-14 (1)', 'AU-3 f', 'AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-6 (4)', 'AU-7 (1)', 'AU-7 a', 'MA-4 (1) (a)']
end

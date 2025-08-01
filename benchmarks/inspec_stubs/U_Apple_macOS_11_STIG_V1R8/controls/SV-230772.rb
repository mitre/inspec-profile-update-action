control 'SV-230772' do
  title 'The macOS system must initiate session audits at system startup, using internal clocks with time stamps for audit records that meet a minimum granularity of one second and can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT), to generate audit records containing information to establish what type of events occurred, the identity of any individual or process associated with the event, including individual identities of group account users, establish where the events occurred, source of the event, and outcome of the events including all account enabling actions, full-text recording of privileged commands, and information about the use of encryption for access wireless access to and from the system.'
  desc 'Without establishing what type of events occurred, when they occurred, and by whom it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the operating system audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured operating system.

'
  desc 'check', 'To check if the audit service is running, use the following command:

launchctl print-disabled system| grep auditd

If the return is not:
"com.apple.auditd" => false"
 the audit service is disabled, and this is a finding.'
  desc 'fix', 'To enable the audit service, run the following command:

/usr/bin/sudo /bin/launchctl enable system/com.apple.auditd

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33717r607203_chk'
  tag severity: 'medium'
  tag gid: 'V-230772'
  tag rid: 'SV-230772r855681_rule'
  tag stig_id: 'APPL-11-001003'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-33690r607204_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000055-GPOS-00026', 'SRG-OS-000254-GPOS-00095', 'SRG-OS-000255-GPOS-00096', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000337-GPOS-00129', 'SRG-OS-000358-GPOS-00145', 'SRG-OS-000359-GPOS-00146']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000159', 'CCI-001464', 'CCI-001487', 'CCI-001889', 'CCI-001890', 'CCI-001914', 'CCI-002130']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-8 a', 'AU-14 (1)', 'AU-3 f', 'AU-8 b', 'AU-8 b', 'AU-12 (3)', 'AC-2 (4)']
end

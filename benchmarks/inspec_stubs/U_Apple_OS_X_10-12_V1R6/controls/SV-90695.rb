control 'SV-90695' do
  title 'The OS X system must initiate session audits at system startup, using internal clocks with time stamps for audit records that meet a minimum granularity of one second and can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT), in order to generate audit records containing information to establish what type of events occurred, the identity of any individual or process associated with the event, including individual identities of group account users, establish where the events occurred, source of the event, and outcome of the events including all account enabling actions, full-text recording of privileged commands, and information about the use of encryption for access wireless access to and from the system.'
  desc 'Without establishing what type of events occurred, when they occurred, and by whom it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the operating system audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured operating system.

'
  desc 'check', 'To check if the audit service is running, use the following command:

/usr/bin/sudo /bin/launchctl list | /usr/bin/grep com.apple.auditd

If nothing is returned, the audit service is not running, and this is a finding.'
  desc 'fix', 'To enable the audit service, run the following command:

/usr/bin/sudo /bin/launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75691r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76007'
  tag rid: 'SV-90695r1_rule'
  tag stig_id: 'AOSX-12-000230'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-82645r1_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000055-GPOS-00026', 'SRG-OS-000254-GPOS-00095', 'SRG-OS-000255-GPOS-00096', 'SRG-OS-000255-GPOS-00096', 'SRG-OS-000299-GPOS-00117', 'SRG-OS-000303-GPOS-00120', 'SRG-OS-000358-GPOS-00145', 'SRG-OS-000359-GPOS-00146']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000159', 'CCI-001444', 'CCI-001464', 'CCI-001487', 'CCI-001889', 'CCI-001890', 'CCI-002130']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-8 a', 'AC-18 (1)', 'AU-14 (1)', 'AU-3 f', 'AU-8 b', 'AU-8 b', 'AC-2 (4)']
end

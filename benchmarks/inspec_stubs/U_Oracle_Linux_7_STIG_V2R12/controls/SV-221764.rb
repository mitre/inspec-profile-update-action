control 'SV-221764' do
  title 'The Oracle Linux operating system must be configured so that auditing is configured to produce records containing information to establish what type of events occurred, where the events occurred, the source of the events, and the outcome of the events. These audit records must also identify individual identities of group account users.'
  desc 'Without establishing what type of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the operating system audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds, or identifying an improperly configured operating system.

'
  desc 'check', 'Verify the operating system produces audit records containing information to establish when (date and time) the events occurred.

Check to see if auditing is active by issuing the following command:

# systemctl is-active auditd.service
active

If the "auditd" status is not active, this is a finding.'
  desc 'fix', 'Configure the operating system to produce audit records containing information to establish when (date and time) the events occurred.

Enable the auditd service with the following command:

# systemctl start auditd.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36286r602452_chk'
  tag severity: 'medium'
  tag gid: 'V-221764'
  tag rid: 'SV-221764r860865_rule'
  tag stig_id: 'OL07-00-030000'
  tag gtitle: 'SRG-OS-000038-GPOS-00016'
  tag fix_id: 'F-36250r602453_fix'
  tag satisfies: ['SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000254-GPOS-00095', 'SRG-OS-000365-GPOS-00152', 'SRG-OS-000255-GPOS-00096']
  tag 'documentable'
  tag legacy: ['V-99267', 'SV-108371']
  tag cci: ['CCI-000131', 'CCI-000132', 'CCI-000135', 'CCI-001464', 'CCI-001487', 'CCI-001814']
  tag nist: ['AU-3 b', 'AU-3 c', 'AU-3 (1)', 'AU-14 (1)', 'AU-3 f', 'CM-5 (1)']
end

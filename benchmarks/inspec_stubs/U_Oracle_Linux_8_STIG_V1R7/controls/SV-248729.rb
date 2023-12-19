control 'SV-248729' do
  title 'The OL 8 audit system must audit local events.'
  desc 'Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.'
  desc 'check', 'Verify the OL 8 Audit Daemon is configured to include local events, with the following command:

$ sudo grep local_events /etc/audit/auditd.conf

local_events = yes

If the value of the "local_events" option is not set to "yes", or the line is commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to audit local events on the system.

Add or update the following line in "/etc/audit/auditd.conf" file:

local_events = yes'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52163r779751_chk'
  tag severity: 'medium'
  tag gid: 'V-248729'
  tag rid: 'SV-248729r779753_rule'
  tag stig_id: 'OL08-00-030061'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52117r779752_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

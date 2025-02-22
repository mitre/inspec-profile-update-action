control 'SV-253052' do
  title 'The TOSS audit system must audit local events.'
  desc 'Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.'
  desc 'check', 'Verify the TOSS audit Daemon is configured to include local events, with the following command:

$ sudo grep local_events /etc/audit/auditd.conf

local_events = yes

If the value of the "local_events" option is not set to "yes", or the line is commented out, this is a finding.'
  desc 'fix', 'Configure TOSS to audit local events on the system.

Add or update the following line in "/etc/audit/auditd.conf" file:

local_events = yes'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56505r824826_chk'
  tag severity: 'medium'
  tag gid: 'V-253052'
  tag rid: 'SV-253052r824828_rule'
  tag stig_id: 'TOSS-04-031350'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56455r824827_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

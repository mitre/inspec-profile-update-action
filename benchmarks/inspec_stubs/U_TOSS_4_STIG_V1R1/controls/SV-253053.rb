control 'SV-253053' do
  title 'TOSS must resolve audit information before writing to disk.'
  desc 'Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Enriched logging aids in making sense of who, what, and when events occur on a system. Without this, determining root cause of an event will be much more difficult.'
  desc 'check', 'Verify the TOSS audit daemon is configured to resolve audit information before writing to disk, with the following command:

$ sudo grep "log_format" /etc/audit/auditd.conf

log_format = ENRICHED

If the "log_format" option is not "ENRICHED", or the line is commented out, this is a finding.'
  desc 'fix', 'Edit the /etc/audit/auditd.conf file and add or update the "log_format" option:

log_format = ENRICHED

The audit daemon must be restarted for changes to take effect.'
  impact 0.3
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56506r824829_chk'
  tag severity: 'low'
  tag gid: 'V-253053'
  tag rid: 'SV-253053r824831_rule'
  tag stig_id: 'TOSS-04-031360'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56456r824830_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

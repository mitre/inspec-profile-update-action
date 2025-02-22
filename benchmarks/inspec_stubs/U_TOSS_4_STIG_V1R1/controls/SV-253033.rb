control 'SV-253033' do
  title 'TOSS must label all off-loaded audit logs before sending them to the central log server.'
  desc 'Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Enriched logging is needed to determine who, what, and when events occur on a system. Without this, determining root cause of an event will be much more difficult.

When audit logs are not labeled before they are sent to a central log server, the audit data will not be able to be analyzed and tied back to the correct system.

'
  desc 'check', 'Verify the TOSS audit Daemon is configured to label all off-loaded audit logs, with the following command:

$ sudo grep "name_format" /etc/audit/auditd.conf

name_format = hostname

If the "name_format" option is not "hostname", "fqd", or "numeric", or the line is commented out, this is a finding.'
  desc 'fix', 'Edit the /etc/audit/auditd.conf file and add or update the "name_format" option to one of "hostname", "fqd", or "numeric":

name_format = hostname

The audit daemon must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56486r824769_chk'
  tag severity: 'medium'
  tag gid: 'V-253033'
  tag rid: 'SV-253033r824771_rule'
  tag stig_id: 'TOSS-04-030910'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-56436r824770_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

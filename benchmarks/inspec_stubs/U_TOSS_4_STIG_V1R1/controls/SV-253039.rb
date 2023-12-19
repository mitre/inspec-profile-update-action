control 'SV-253039' do
  title 'Successful/unsuccessful modifications to the "lastlog" file in TOSS must generate an audit record.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'Verify TOSS generates an audit record when successful/unsuccessful modifications to the "lastlog" file by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w lastlog /etc/audit/audit.rules

-w /var/log/lastlog -p wa -k logins

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful modifications to the "lastlog" file by adding or updating the following rules in the "/etc/audit/rules.d/audit.rules" file:

-w /var/log/lastlog -p wa -k logins

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56492r824787_chk'
  tag severity: 'medium'
  tag gid: 'V-253039'
  tag rid: 'SV-253039r824789_rule'
  tag stig_id: 'TOSS-04-031130'
  tag gtitle: 'SRG-OS-000470-GPOS-00214'
  tag fix_id: 'F-56442r824788_fix'
  tag satisfies: ['SRG-OS-000470-GPOS-00214', 'SRG-OS-000473-GPOS-00218']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

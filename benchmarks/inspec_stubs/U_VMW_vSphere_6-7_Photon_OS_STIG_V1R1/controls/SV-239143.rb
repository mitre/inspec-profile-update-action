control 'SV-239143' do
  title 'The Photon operating system must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

'
  desc 'check', 'At the command line, execute the following command:

# auditctl -l | grep -E "faillog|lastlog|tallylog"

Expected result:

-w /var/log/faillog -p wa
-w /var/log/lastlog -p wa
-w /var/log/tallylog -p wa

If the output does not match the expected result, this is a finding.'
  desc 'fix', "At the command line, execute the following commands:

# echo '-w /var/log/faillog -p wa' >> /etc/audit/rules.d/audit.STIG.rules
# echo '-w /var/log/lastlog -p wa' >> /etc/audit/rules.d/audit.STIG.rules
# echo '-w /var/log/tallylog -p wa' >> /etc/audit/rules.d/audit.STIG.rules
# /sbin/augenrules --load"
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42354r675235_chk'
  tag severity: 'medium'
  tag gid: 'V-239143'
  tag rid: 'SV-239143r675237_rule'
  tag stig_id: 'PHTN-67-000072'
  tag gtitle: 'SRG-OS-000470-GPOS-00214'
  tag fix_id: 'F-42313r675236_fix'
  tag satisfies: ['SRG-OS-000470-GPOS-00214', 'SRG-OS-000472-GPOS-00217', 'SRG-OS-000473-GPOS-00218']
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

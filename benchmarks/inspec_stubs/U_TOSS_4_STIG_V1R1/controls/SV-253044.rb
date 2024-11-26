control 'SV-253044' do
  title 'Successful/unsuccessful uses of the "su" command in TOSS must generate an audit record.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The "su" command allows a user to run commands with a substitute user and group ID.'
  desc 'check', 'Verify TOSS generates audit records when successful/unsuccessful attempts to use the "su" command by performing the following command to check the file system rules in "/etc/audit/audit.rules": 

$ sudo grep -w /usr/bin/su /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure TOSS to generate audit records when successful/unsuccessful attempts to use the "su" command occur by adding or updating the following rule in "/etc/audit/rules.d/audit.rules":

-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56497r824802_chk'
  tag severity: 'medium'
  tag gid: 'V-253044'
  tag rid: 'SV-253044r824804_rule'
  tag stig_id: 'TOSS-04-031180'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-56447r824803_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

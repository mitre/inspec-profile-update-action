control 'SV-253047' do
  title 'Successful/unsuccessful uses of the "usermod" command in TOSS must generate an audit record.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The "usermod" command modifies the system account files to reflect the changes that are specified on the command line.'
  desc 'check', 'Verify that an audit event is generated for any successful/unsuccessful use of the "usermod" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w usermod /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k privileged

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "usermod" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k privileged

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56500r824811_chk'
  tag severity: 'medium'
  tag gid: 'V-253047'
  tag rid: 'SV-253047r824813_rule'
  tag stig_id: 'TOSS-04-031210'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-56450r824812_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

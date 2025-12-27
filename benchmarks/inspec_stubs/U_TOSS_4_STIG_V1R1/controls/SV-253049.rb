control 'SV-253049' do
  title 'Successful/unsuccessful uses of "userhelper" in TOSS must generate an audit record.'
  desc %q(Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The "userhelper" command is not intended to be run interactively. "Userhelper" provides a basic interface to change a user's password, gecos information, and shell. The main difference between this program and its traditional equivalents (passwd, chfn, chsh) is that prompts are written to standard out to make it easy for a graphical user interface wrapper to interface to it as a child process.)
  desc 'check', 'Verify that an audit event is generated for any successful/unsuccessful use of "userhelper" by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w "userhelper" /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=unset -k privileged

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "userhelper" by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=unset -k privileged

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56502r824817_chk'
  tag severity: 'medium'
  tag gid: 'V-253049'
  tag rid: 'SV-253049r824819_rule'
  tag stig_id: 'TOSS-04-031230'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-56452r824818_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

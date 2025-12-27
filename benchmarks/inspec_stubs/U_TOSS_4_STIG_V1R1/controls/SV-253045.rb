control 'SV-253045' do
  title 'Successful/unsuccessful uses of the "umount" command in TOSS must generate an audit record.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

The "umount" command is used to unmount a filesystem.'
  desc 'check', 'Verify that an audit event is generated for any successful/unsuccessful use of the "umount" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w /usr/bin/umount /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -k privileged

If the command does not return a line, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "umount" command by adding or updating the following rules in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -k privileged

The audit daemon must be restarted for the changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56498r824805_chk'
  tag severity: 'medium'
  tag gid: 'V-253045'
  tag rid: 'SV-253045r824807_rule'
  tag stig_id: 'TOSS-04-031190'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-56448r824806_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

control 'SV-223714' do
  title 'IBM RACF assignment of the RACF OPERATIONS attribute to individual userids must be fully justified.'
  desc 'This requirement is intended to cover both traditional interactive logons to information systems and general accesses to information systems that occur in other types of architectural configurations (e.g., service-oriented architectures).'
  desc 'check', 'From the ISPF Command Shell enter:
ListUser *

If authorization to the SYSTEM OPERATIONS attribute is restricted to key systems personnel such as individuals responsible for continuing operations, Storage Management, and emergency recovery, this is not a finding.

If any users connected to sensitive system dataset HLQ (e.g., SYS1, SYS2, ETC) groups with the Group-OPERATIONS are key systems personnel, such as individuals responsible for continuing operations, Storage Management, and emergency recovery, this is a finding.

Otherwise, Group-OPERATIONS is allowed.'
  desc 'fix', 'Review all USERIDs with the OPERATIONS attribute. Ensure documentation providing justification for access is maintained and filed with the ISSO, and that unjustified access is removed.

A sample command to remove the OPERATIONS attribute from a userid is shown here: 

ALU <userid> NOOPERATIONS

To remove the Group-Operations attribute:

CO <user> GROUP(<groupname>) NOOPERATIONS'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25387r571992_chk'
  tag severity: 'medium'
  tag gid: 'V-223714'
  tag rid: 'SV-223714r604139_rule'
  tag stig_id: 'RACF-ES-000670'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25375r514831_fix'
  tag 'documentable'
  tag legacy: ['V-98135', 'SV-107239']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

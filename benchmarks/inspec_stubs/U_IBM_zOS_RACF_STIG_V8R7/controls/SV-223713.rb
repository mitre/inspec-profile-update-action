control 'SV-223713' do
  title 'IBM RACF use of the RACF SPECIAL Attribute must be justified.'
  desc 'The organization must perform a periodic scan/review of the application (as required by CCI-000384) and disable functions, ports, protocols, and services deemed to be unneeded or non-secure.'
  desc 'check', 'From the ISPF Command Shell enter:
ListUser *

If authorization to the SYSTEM SPECIAL attribute is restricted to key systems personnel such as individuals responsible for continuing operations, Storage Management, and emergency recovery, this is not a finding.

If any users connected to sensitive system dataset HLQ (e.g., SYS1, SYS2, ETC) groups with the Group-SPECIAL are key systems personnel, such as individuals responsible for continuing operations, Storage Management, and emergency recovery, this is a finding.

Otherwise, Group-SPECIAL is allowed.'
  desc 'fix', 'Review all USERIDs with the SPECIAL attribute. Ensure documentation providing justification for access is maintained and filed with the ISSO, and that unjustified access is removed.

For the SYSTEM SPECIAL attribute:

A sample command for removing the SPECIAL attribute is shown here: ALU <userid> NOSPECIAL.

For the GROUP SPECIAL attribute:

CO <user> GROUP(<groupname>) NOSPECIAL'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25386r571990_chk'
  tag severity: 'medium'
  tag gid: 'V-223713'
  tag rid: 'SV-223713r604139_rule'
  tag stig_id: 'RACF-ES-000660'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25374r514828_fix'
  tag 'documentable'
  tag legacy: ['V-98133', 'SV-107237']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

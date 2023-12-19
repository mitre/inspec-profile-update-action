control 'SV-223858' do
  title 'IBM z/OS UNIX groups must be defined with a unique GID.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'From the ISPF Command Shell enter: 
Listgrp * OMVS

If each group is defined with a unique GID, this is not a finding.'
  desc 'fix', 'Define each UNIX group with a unique GID.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25531r515262_chk'
  tag severity: 'medium'
  tag gid: 'V-223858'
  tag rid: 'SV-223858r604139_rule'
  tag stig_id: 'RACF-US-000210'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25519r515263_fix'
  tag 'documentable'
  tag legacy: ['V-98423', 'SV-107527']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

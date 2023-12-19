control 'SV-224093' do
  title 'The IBM z/OS user account for the UNIX kernel (OMVS) must be properly defined to the security database.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'If OMVS userid is defined to the ESM as follows, this is not a finding.

-No access to interactive on-line facilities (e.g., TSO, CICS, etc.)
-Default group specified as OMVSGRP or STCOMVS
-UID(0)
-HOME directory specified as "/"
-Shell program specified as "/bin/sh"'
  desc 'fix', 'Define OMVS userid to the ESM as specified below:

-No access to interactive on-line facilities (e.g., TSO, CICS, etc.)
-Default group specified as OMVSGRP or STCOMVS
-UID(0)
-HOME directory specified as "/"
-Shell program specified as "/bin/sh"'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25766r516678_chk'
  tag severity: 'medium'
  tag gid: 'V-224093'
  tag rid: 'SV-224093r877931_rule'
  tag stig_id: 'TSS0-US-000200'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25754r516679_fix'
  tag 'documentable'
  tag legacy: ['SV-107997', 'V-98893']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

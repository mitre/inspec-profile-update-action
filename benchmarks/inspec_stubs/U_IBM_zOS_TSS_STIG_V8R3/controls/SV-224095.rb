control 'SV-224095' do
  title 'The IBM z/OS user account for the UNIX (RMFGAT) must be properly defined.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'RMFGAT is the userid for the Resource Measurement Facility (RMF) Monitor III Gatherer. If RMFGAT is not define this is not applicable.

From a command input screen enter:

TSS LIST (RMFGAT) DATA ALL

If RMFGAT is defined as follows, this is not a finding:

-Default group specified as OMVSGRP or STCOMVS
-A unique, non-zero UID
 -HOME directory specified as "/"
 -Shell program specified as "/bin/sh"'
  desc 'fix', 'Define RMFGAT user account is defined as specified below:

-Default group specified as OMVSGRP or STCOMVS
-A unique, non-zero UID
-HOME directory specified as "/"
-Shell program specified as "/bin/sh"'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25768r516684_chk'
  tag severity: 'medium'
  tag gid: 'V-224095'
  tag rid: 'SV-224095r561402_rule'
  tag stig_id: 'TSS0-US-000220'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25756r516685_fix'
  tag 'documentable'
  tag legacy: ['SV-108001', 'V-98897']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

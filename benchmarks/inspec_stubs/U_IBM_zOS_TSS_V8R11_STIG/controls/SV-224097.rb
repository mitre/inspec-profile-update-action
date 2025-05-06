control 'SV-224097' do
  title 'IBM z/OS UNIX user accounts must be properly defined.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'NOTE: This only applies to users of z/OS UNIX (i.e., users with an OMVS profile defined).

From the ISPF Command Shell enter:
TSS LIST(ACIDS) SEGMENT(OMVS)

If any user account is not defined as follows, this is a finding.

-A unique UID number (except for UID(0) users)
-A unique HOME directory (except for UID(0) and other system task accounts)
-Shell program specified as "/bin/sh", "/bin/tcsh", "/bin/echo", or "/bin/false"

NOTE: The shell program must have one of the specified values. The HOME directory must have a value (i.e., not be allowed to default).'
  desc 'fix', 'Configure each user account to be defined as specified below:

NOTE: This only applies to users of z/OS UNIX (i.e., users with an OMVS profile defined).

-A unique UID number (except for UID(0) users)
-A unique HOME directory (except for UID(0) and other system task accounts)
-Shell program specified as "/bin/sh", "/bin/tcsh", "/bin/echo", or "/bin/false"

NOTE: The shell program must have one of the specified values. The HOME directory must have a value (i.e., not be allowed to default).'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25770r516690_chk'
  tag severity: 'medium'
  tag gid: 'V-224097'
  tag rid: 'SV-224097r877935_rule'
  tag stig_id: 'TSS0-US-000240'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25758r516691_fix'
  tag 'documentable'
  tag legacy: ['SV-108005', 'V-98901']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

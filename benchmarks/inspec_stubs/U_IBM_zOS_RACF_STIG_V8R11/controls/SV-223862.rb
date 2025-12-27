control 'SV-223862' do
  title 'IBM z/OS UNIX user accounts must be properly defined.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'From a z/OS command screen enter:
LISTUSER * OMVS NORACF

NOTE: This check only applies to users of z/OS UNIX (i.e., users with an OMVS profile defined).

If each user account with an OMVS segment is defined as follows, this is not a finding.

-A unique UID number (except for UID(0) users)
-A unique HOME directory (except for UID(0) and other system task accounts)
-Shell program specified as "/bin/sh", "/bin/tcsh", "/bin/echo", or "/bin/false"

NOTE: The shell program must have one of the specified values. The HOME directory must have a value (i.e., not be allowed to default).'
  desc 'fix', 'Define users of z/OS UNIX (i.e., users with an OMVS profile defined) as follows:

-A unique UID number (except for UID(0) users)
-A unique HOME directory (except for UID(0) and other system task accounts)
-Shell program specified as "/bin/sh", "/bin/tcsh", "/bin/echo", or "/bin/false"

NOTE: The shell program must have one of the specified values. The HOME directory must have a value (i.e., not be allowed to default).'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25535r868917_chk'
  tag severity: 'medium'
  tag gid: 'V-223862'
  tag rid: 'SV-223862r868919_rule'
  tag stig_id: 'RACF-US-000250'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25523r868918_fix'
  tag 'documentable'
  tag legacy: ['SV-107535', 'V-98431']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

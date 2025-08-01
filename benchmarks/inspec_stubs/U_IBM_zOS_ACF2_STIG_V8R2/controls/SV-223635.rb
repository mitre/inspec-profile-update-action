control 'SV-223635' do
  title 'IBM z/OS UNIX user accounts must be properly defined.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'From an ACF Command screen enter:
SET LID
LIST IF(OMVSUSER)

If each user account is defined as follows this is not a finding.
A unique UID number (except for UID(0) users)
A unique HOME directory (except for UID(0) and other system task accounts)
Shell program specified as “/bin/sh”, “/bin/tcsh”, “/bin/echo”, or “/bin/false”

NOTE: The shell program must have one of the specified values. The HOME directory must have a value (i.e., not be allowed to default).'
  desc 'fix', 'Define any z/OS UNIX user as follows:
 A unique UID number (except for UID(0) users)
 A unique HOME directory (except for UID(0) and other system task accounts)
 Shell program specified as "/bin/sh", "/bin/tcsh", "/bin/echo", or "/bin/false"

NOTE: The shell program must have one of the specified values. The HOME directory must have a value (i.e., not be allowed to default).'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25308r504863_chk'
  tag severity: 'medium'
  tag gid: 'V-223635'
  tag rid: 'SV-223635r533198_rule'
  tag stig_id: 'ACF2-US-000200'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25296r504864_fix'
  tag 'documentable'
  tag legacy: ['V-97975', 'SV-107079']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

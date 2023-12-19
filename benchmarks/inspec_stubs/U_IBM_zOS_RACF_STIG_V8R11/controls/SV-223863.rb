control 'SV-223863' do
  title 'IBM z/OS attributes of UNIX user accounts used for account modeling must be defined in accordance with security requirements.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'If this is a Classified system, and there is an account used for modeling, this is a finding.

From a command input screen enter:
RLIST FACILITY (BPX.UNIQUE.USER) ALL
Examine APPLICATION DATA for userid

Enter:
List User (<userid>)

Note: This check applies to any user id used to model OMVS access on the mainframe. This includes the OMVS default user and BPX.UNIQUE.USER. If the OMVS default user or BPX.UNIQUE.USER is not defined in the FACILITY report, this is Not Applicable.

If user account used for OMVS account modeling is defined as follows, this is not a finding:

A non-writable HOME directory:
Shell program specified as "/bin/echo" or "/bin/false"

Note: The shell program must have one of the specified values. The HOME directory must have a value (i.e., not be allowed to default).'
  desc 'fix', 'Use of the OMVS default UID will not be allowed on any Classified system. This is not an issue when using BPX.UNIQUE.USER.

Define user id used for OMVS account modeling with a non-0 UID, a nonwritable home directory, such as "\\" root, and a nonexecutable, but existing, binary file, "/bin/false" or "/bin/echo."'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25536r868920_chk'
  tag severity: 'medium'
  tag gid: 'V-223863'
  tag rid: 'SV-223863r868922_rule'
  tag stig_id: 'RACF-US-000260'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25524r868921_fix'
  tag 'documentable'
  tag legacy: ['V-98433', 'SV-107537']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

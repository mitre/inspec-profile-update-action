control 'SV-224098' do
  title 'IBM z/OS attributes of UNIX user accounts used for account modeling must be defined in accordance with security requirements.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS LIST(ACIDS) DATA(NAME) SEGMENT(OMVS)
This check applies to any user identifier (ACID) used to model OMVS access on the mainframe. This includes OMVSUSR; MODLUSER, and BPX.UNIQUE.USER.
 ENTER 
TSS MODIFY STATUS

If ANY MODLUSER is specified then UNIQUSER must be specified as "ON" in the STATUS.

If user identifier (ACID) used to model OMVS user account is defined as follows, this is not finding.

A non-writable HOME directory
Shell program specified as "/bin/echo", or "/bin/false"

Note: The shell program must have one of the specified values. The HOME directory must have a value (i.e., not be allowed to default).'
  desc 'fix', 'Use of the OMVS default UID will not be allowed on any classified system.

Define the user identifier (ACID) used to model OMVS user account with a non-writable home directory, such as "\\" root, and a non-executable, but existing, binary file, "/bin/false" or "/bin/echo."'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25771r516693_chk'
  tag severity: 'medium'
  tag gid: 'V-224098'
  tag rid: 'SV-224098r877936_rule'
  tag stig_id: 'TSS0-US-000250'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25759r516694_fix'
  tag 'documentable'
  tag legacy: ['SV-108007', 'V-98903']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

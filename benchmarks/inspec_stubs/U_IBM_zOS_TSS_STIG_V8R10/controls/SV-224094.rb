control 'SV-224094' do
  title 'The IBM z/OS user account for the z/OS UNIX SUPERUSER userid must be properly defined.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'Refer to system PARMLIB member BPXPRMxx (xx is determined by OMVS entry in IEASYS00.) 

Determine the user ID identified by the SUPERUSER parameter. (BPXROOT is the default).

From a command input screen enter:
LISTUSER (superuser userid) TSO CICS OMVS

If the SUPERUSER userid is defined as follows, this is not a finding:

- No access to interactive on-line facilities (e.g., TSO, CICS, etc.)
- Default group specified as OMVSGRP or STCOMVS
- UID(0)
- HOME directory specified as "/"
- Shell program specified as "/bin/sh"'
  desc 'fix', 'Define the user ID identified in the BPXPRM00 SUPERUSER parameter as specified below:

- No access to interactive on-line facilities (e.g., TSO, CICS, etc.)
- Default group specified as OMVSGRP or STCOMVS
- UID(0)
- HOME directory specified as "/"
- Shell program specified as "/bin/sh"'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25767r516681_chk'
  tag severity: 'medium'
  tag gid: 'V-224094'
  tag rid: 'SV-224094r877932_rule'
  tag stig_id: 'TSS0-US-000210'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25755r516682_fix'
  tag 'documentable'
  tag legacy: ['SV-107999', 'V-98895']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

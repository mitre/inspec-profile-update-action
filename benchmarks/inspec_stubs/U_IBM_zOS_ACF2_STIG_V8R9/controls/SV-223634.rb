control 'SV-223634' do
  title 'IBM z/OS user account for the z/OS UNIX SUPERSUSER userid must be properly defined.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'Refer to system PARMLIB member BPXPRMxx (xx is determined by OMVS entry in IEASYS00.) 
Determine the user ID identified by the SUPERUSER parameter. (BPXROOT is the default).
From a command input screen enter:
SET LID 
LIST LIKE (superuser userid)

If the SUPERUSER userid is defined as follows, this is not a finding.
- No access to interactive on-line facilities (e.g., TSO, CICS, etc.)
- Default group specified as OMVSGRP or STCOMVS

From an ACF command input screen enter:
SET PROFILE(USER) DIVISION(OMVS) 
SET VERBOSE 
LIST <superuser userid> 

If the SUPERUSER userid is defined as follows, this is not a finding:
- UID(0)
- HOME directory specified as "/"
- Shell program specified as "/bin/sh"'
  desc 'fix', 'Define the user ID identified in the BPXPRM00 SUPERUSER parameter as specified below:
No access to interactive on-line facilities (e.g., TSO, CICS, etc)
Default group specified as OMVSGRP or STCOMVS
UID(0)
HOME directory specified as "/"
Shell program specified as "/bin/sh"'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25307r858913_chk'
  tag severity: 'medium'
  tag gid: 'V-223634'
  tag rid: 'SV-223634r861192_rule'
  tag stig_id: 'ACF2-US-000190'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25295r504861_fix'
  tag 'documentable'
  tag legacy: ['V-97973', 'SV-107077']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

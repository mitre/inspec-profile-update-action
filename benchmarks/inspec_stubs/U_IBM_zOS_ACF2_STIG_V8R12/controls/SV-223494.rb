control 'SV-223494' do
  title 'IBM z/OS user account for the UNIX kernel (OMVS) must be properly defined to the security database.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF
SET LID
SET VERBOSE
LIST OMVS SECTION(ALL) PROFILE(OMVS)

If OMVS is defined as follows, this is not a finding.

No access to interactive on-line facilities (e.g., TSO, CICS, etc).
Default group specified as OMVSGRP or STCOMVS
UID(0)
HOME directory specified as "/"
Shell program specified as "/bin/sh"

If OMVS is not defined as specified in above, this is a finding.'
  desc 'fix', 'Define the OMVS (IBM default name for USS Kernel), as specified below:

No access to interactive on-line facilities (e.g., TSO, CICS, etc.)
Default group specified as OMVSGRP or STCOMVS
UID(0)
HOME directory specified as "/"
Shell program specified as "/bin/sh"'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25167r836649_chk'
  tag severity: 'medium'
  tag gid: 'V-223494'
  tag rid: 'SV-223494r836650_rule'
  tag stig_id: 'ACF2-ES-000760'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25155r504586_fix'
  tag 'documentable'
  tag legacy: ['SV-106791', 'V-97687']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

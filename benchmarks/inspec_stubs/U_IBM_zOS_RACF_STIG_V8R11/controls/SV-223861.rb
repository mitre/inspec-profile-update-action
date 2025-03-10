control 'SV-223861' do
  title 'The IBM z/OS user account for the UNIX (RMFGAT) must be properly defined.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'RMFGAT is the userid for the Resource Measurement Facility (RMF) Monitor III Gatherer. 

If RMFGAT is not defined, this is Not Applicable.

From a command input screen enter:
LISTUSER (RMFGAT) OMVS

If RMFGAT is defined as follows, this is not a finding.

Default group specified as OMVSGRP or STCOMVS
A unique, non-zero UID
HOME directory specified as "/"
Shell program specified as "/bin/sh"'
  desc 'fix', 'Define the RMFGAT user account as specified below:

Default group specified as OMVSGRP or STCOMVS
A unique, non-zero UID
HOME directory specified as "/"
Shell program specified as "/bin/sh"'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25534r868914_chk'
  tag severity: 'medium'
  tag gid: 'V-223861'
  tag rid: 'SV-223861r868916_rule'
  tag stig_id: 'RACF-US-000240'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25522r868915_fix'
  tag 'documentable'
  tag legacy: ['SV-107533', 'V-98429']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

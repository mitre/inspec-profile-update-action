control 'SV-223495' do
  title 'IBM z/OS user account for the UNIX (RMFGAT) must be properly defined.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'RMFGAT is the userid for the Resource Measurement Facility (RMF) Monitor III Gatherer. If RMFGAT is not define, this is Not Applicable.

From the ISPF Command Shell enter:
ACF
SET LID
SET VERBOSE
LIST RMFGAT SECTION(ALL) PROFILE(OMVS)

If RMFGAT is defined as follows, this is not a finding:
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
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25168r858856_chk'
  tag severity: 'medium'
  tag gid: 'V-223495'
  tag rid: 'SV-223495r861168_rule'
  tag stig_id: 'ACF2-ES-000770'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25156r858857_fix'
  tag 'documentable'
  tag legacy: ['V-97689', 'SV-106793']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

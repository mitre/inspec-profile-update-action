control 'SV-224092' do
  title 'IBM z/OS attributes of z/OS UNIX user accounts must have a unique GID in the range of 1-99.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'A site can choose to have both an OMVSGRP group and an STCOMVS group or combine the groups under one of these names.

If OMVSGRP and/or STCOMVS groups are defined and have a unique GID in the range of 1-99 this is not a finding.'
  desc 'fix', 'Define the OMVSGRP group and / or the STCOMVS group to the security database with a unique GID in the range of 1-99.

OMVSGRP is the name suggested by IBM for all the required userids. STCOMVS is the standard name used at some sites for the userids that are associated with z/OS UNIX started tasks and daemons. These groups can be combined at the site’s discretion.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25765r516675_chk'
  tag severity: 'medium'
  tag gid: 'V-224092'
  tag rid: 'SV-224092r561402_rule'
  tag stig_id: 'TSS0-US-000190'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25753r516676_fix'
  tag 'documentable'
  tag legacy: ['SV-107995', 'V-98891']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

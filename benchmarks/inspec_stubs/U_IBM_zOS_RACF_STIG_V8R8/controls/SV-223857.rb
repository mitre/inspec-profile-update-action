control 'SV-223857' do
  title 'IBM z/OS UNIX groups must be defined with a unique GID.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. RACF userid groups, and started tasks that use z/OS UNIX facilities are defined to an ACP with attributes including UID and GID. If these attributes are not correctly defined, data access or command privilege controls could be compromised.'
  desc 'check', 'From ISPF Command Shell enter:
Listgrp * OMVS

If each group is defined with a unique GID, this is not a finding.

Note: A site can choose to have both an OMVSGRP group and an STCOMVS group or combine the groups under one of these names.

If OMVSGRP and/or STCOMVS groups are defined and have a unique GID in the range of 1-99, this is not a finding.'
  desc 'fix', 'Define each UNIX group with a unique GID.

Define the OMVSGRP group and/or the STCOMVS group to the security database with a unique GID in the range of 1-99.

OMVSGRP is the name suggested by IBM for all the required userids. STCOMVS is the standard name used at some sites for the userids that are associated with z/OS UNIX started tasks and daemons. These groups can be combined at the site’s discretion.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25530r767100_chk'
  tag severity: 'medium'
  tag gid: 'V-223857'
  tag rid: 'SV-223857r767121_rule'
  tag stig_id: 'RACF-US-000200'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25518r767101_fix'
  tag 'documentable'
  tag legacy: ['V-98421', 'SV-107525']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end

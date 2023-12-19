control 'SV-6724' do
  title 'The default zone visibility setting is not set to “none”.'
  desc 'If the default zone visibility setting is set to "none", new clients brought into the SAN will not be allowed access to any SAN zone they are not explicitly placed into.
The IAO/NSO will ensure that the default zone visibility setting, if available, is set to “none”.'
  desc 'check', 'Reviewer with the assistance of the IAO/NSO, verify that the default zone visibility setting is set to “none”..  If this setting is not available mark this check as N/A.'
  desc 'fix', 'Locate all clients that have not been explicitly placed into a zone.  Create a plan to explicitly place these clients into the correct zone(s) and after doing so the plan will include the modification of the default zone visibility setting to “none”. Obtain CM approval of the plan and then, following the plan, reconfigure the SAN to allow for the default zone visibility setting to be set to “none”.'
  impact 0.5
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2429r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6605'
  tag rid: 'SV-6724r1_rule'
  tag stig_id: 'SAN03.003.00'
  tag gtitle: 'The default zone visibility is not set to "none"'
  tag fix_id: 'F-6189r1_fix'
  tag 'documentable'
  tag potential_impacts: 'If there are client systems that have not explicitly been placed in a zone they may be denied access to data they need.'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
end

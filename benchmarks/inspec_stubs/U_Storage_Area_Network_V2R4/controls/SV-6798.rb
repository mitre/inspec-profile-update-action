control 'SV-6798' do
  title 'Simple Network Management Protocol (SNMP) is used and it is not configured in accordance with the guidance contained in the Network Infrastructure STIG.'
  desc 'There are vulnerabilities in some implementations and some configurations of SNMP.  Therefore if SNMP is used the guidelines found in the Network Infrastructure STIG in selecting a version of SNMP to use and how to configure it will be followed.

If Simple Network Management Protocol (SNMP) is used, the IAO/NSO will ensure it is configured in accordance with the guidance contained in the Network Infrastructure STIG.'
  desc 'check', 'With the assistance of the IAO/NSO, verify that if Simple Network Management Protocol (SNMP) is used, it is configured in accordance with the guidance contained in the Network Infrastructure STIG.

NOTE: The intent of this check is to ensure that the other checklists were applied. If they are applied then, regardless of what the findings are, this is not a finding. The objective of this policy is met if the other checklist was applied and documented.'
  desc 'fix', 'Develop a plan to implement SNMP that is compliant with the Network Infrastructure STIG.  Obtain CM approval and execute the plan.

NOTE: The intent of this check is to ensure that the other applicable checklists were applied. If they are applied then, regardless of what the findings are, this is not a finding. The objective of this policy is met if the other checklists were applied and documented.'
  impact 0.5
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2576r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6652'
  tag rid: 'SV-6798r1_rule'
  tag stig_id: 'SAN04.021.00'
  tag gtitle: 'SNMP usage and configuration.'
  tag fix_id: 'F-6252r1_fix'
  tag 'documentable'
  tag potential_impacts: 'Network monitoring tools that are not modified to match the configuration used for SNMP in the SAN will fail.'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
end

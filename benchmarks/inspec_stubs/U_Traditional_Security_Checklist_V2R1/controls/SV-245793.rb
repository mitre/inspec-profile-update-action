control 'SV-245793' do
  title 'Industrial Security - Contract Guard Vetting'
  desc 'Failure to screen guards could result in employment of unsuitable personnel who are responsible for the safety and security of DOD personnel and facilities.

REFERENCES:

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
PS-2, PS-2(1), PS- 3

DoD Manual 5200.02, Procedures for the DoD Personnel Security Program (PSP), 3 April 2017'
  desc 'check', 'Check to ensure:  

1. Contract guards have a minimum favorable Tier 1 (T1) background investigation (formerly National Agency Check (NAC)) prior to DoD facility assignment or an appropriate level of security clearance if required by the DD 254 and classified duties performed.  

2. If classified work is not required check to ensure security specifications are contained within the contract documentation (Statement of Work (SOW) or other appropriate documentation) for T1/NAC and any other security requirements not involving access to classified.  

3. That contract guards actually have current investigations for the position level of trust and/or security clearance requirements.  

NOTES:  

1. Fully applicable in a tactical environment if contract guards are employed. 

2. This check does not "necessarily" apply to base police/gate guards - only to the guards employed specifically to protect "inspected site" assets. If the host installation employs contract guards to assist or directly protect "inspected site" assets then the requirements of this requirement will apply.'
  desc 'fix', '1. Contract guards must have a minimum favorable Tier 1 (T1) background investigation (formerly National Agency Check (NAC)) prior to DoD facility assignment or an appropriate level of security clearance if required by the DD 254 and classified duties are performed.  

2. If classified work is not required security specifications must be contained within the contract documentation (Statement of Work (SOW) or other appropriate documentation) for a T1/NAC and any other security requirements for guards not involving access to classified.  

NOTES:  

1. Fully applicable in a tactical environment if contract guards are employed. 

2. This check does not "necessarily" apply to base police/gate guards - only to the guards employed specifically to protect "inspected site" assets. If the host installation employs contract guards to assist or directly protect "inspected site" assets then the requirements of this requirement will apply.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49224r770039_chk'
  tag severity: 'medium'
  tag gid: 'V-245793'
  tag rid: 'SV-245793r770041_rule'
  tag stig_id: 'ID-03.02.01'
  tag gtitle: 'ID-03.02.01'
  tag fix_id: 'F-49179r770040_fix'
  tag 'documentable'
  tag legacy: ['V-30995', 'SV-41041r3_rule']
end

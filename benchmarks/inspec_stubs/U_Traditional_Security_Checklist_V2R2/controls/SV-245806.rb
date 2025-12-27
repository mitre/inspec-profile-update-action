control 'SV-245806' do
  title 'Vault/Secure Room Storage Standards - IDS Access/Secure Control Units Must be Located within the Secure Room Space'
  desc 'Failure to ensure that IDS Access and Secure Control Units used to activate and deactivate alarms (primarily motion detectors) within vaults or secure rooms protecting SIPRNet assets are not located within the confines of the vault or secure room near the primary ingress/egress door could result in the observation of the access/secure code by an unauthorized person.  Further the control units would be more exposed with a greater possibility of tampering outside the more highly protected space of a secure room/collateral classified open storage area.  This could result in the undetected breach of secure room space and the loss or compromise of classified information or materials.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
PE-3, PE-5 and PE-6

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Appendix to Enclosure 3, paragraph 2.e.(2).

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, paragraph 5-902.d.'
  desc 'check', 'Requirement Explanation:

Alarm sensor control units must be located inside the secure area and should be located near the primary entrance for ease of accessing and securing alarm sensors in the space.  

Only assigned personnel with proper security clearances and need-to-know should initiate changes in access and secure status.

Check:

Check to ensure that no capability exists to allow changing the access/secure status of the IDS from a location outside the protected area (secure room or vault).  
                         
TACTICAL ENVIRONMENT:  This check is applicable where Vaults/Secure Rooms are used to protect classified materials or systems in a tactical environment. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.'
  desc 'fix', 'No capability must exist to allow for changing the access/secure status of the IDS from a location outside the protected area (secure room or vault). Alarm sensor control units must be located inside the secure area and should be located near the primary entrance for ease of accessing and securing alarm sensors in the space. Only assigned personnel with proper security clearances and need-to-know should initiate changes in access and secure status.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49237r770078_chk'
  tag severity: 'high'
  tag gid: 'V-245806'
  tag rid: 'SV-245806r822858_rule'
  tag stig_id: 'IS-02.01.12'
  tag gtitle: 'IS-02.01.12'
  tag fix_id: 'F-49192r770079_fix'
  tag 'documentable'
  tag legacy: ['V-31292', 'SV-41563r3_rule']
end

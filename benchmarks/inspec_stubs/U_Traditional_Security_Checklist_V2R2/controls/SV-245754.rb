control 'SV-245754' do
  title 'TEMPEST Countermeasures'
  desc 'Failure to implement required TEMPEST countermeasures could leave the system(s) vulnerable to a TEMPEST attack.

REFERENCES: 
                                
CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND)

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 11

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  AC-18, PE-19(1), and SC-8

Committee on National Security Systems Policy 300, "National Policy on Control of Compromising Emanations," April 2004, as amended  
                           
Committee on National Security Systems Instruction 7000, "TEMPEST Countermeasures for Facilities," May 2004, as amended

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014'
  desc 'check', '1. Determine if TEMPEST countermeasures are required based on the geographical location and classification level processed. TEMPEST considerations apply to all OCONUS locations and select CONUS locations.  

2. If required, ask to see a TEMPEST assessment. Verify the TEMPEST assessment was conducted by a Certified TEMPEST Technical Authority (CTTA). 

3. Determine through inspection and/or interview if any required TEMPEST countermeasures are implemented. 
 
4. TEMPEST countermeasures may or may not be feasible in a tactical environment. This can only be determined through a proper Risk Assessment, which is coordinated with a supporting CTTA for matters concerning emanations security.
  
5. Where required (OCONUS in particular) check to ensure an assessment of TEMPEST risk and applicability of countermeasures is included in a risk assessment and that the supporting CTTA was consulted. This process may be conducted by the Major US Combatant Command for Theater level operations rather than by individual units or location based commands. The key element to determine if this requirement is met is that any possible risk resulting from Emanations is properly considered and documented.

NOTES: Where TEMPEST must be considered and although there is no finding, the reviewer should note in the report if a CTTA has conducted a TEMPEST review, the date it was completed and countermeasures recommended. Further note in the report if specific consideration for TEMPEST was provided for in the site risk assessment.'
  desc 'fix', '1. Where TEMPEST is required to be considered a Certified TEMPEST Technical Authority (CTTA) must evaluate Emanation Security concerns and recommended countermeasures from this evaluation must be properly applied.

2. Where TEMPEST is required an assessment of TEMPEST risk and applicability of countermeasures must be included in the site risk assessment and the supporting CTTA must be consulted.

NOTE: TEMPEST countermeasures are required based on the geographical location and classification level processed. TEMPEST considerations apply to all OCONUS locations and select CONUS locations.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49185r769922_chk'
  tag severity: 'medium'
  tag gid: 'V-245754'
  tag rid: 'SV-245754r822821_rule'
  tag stig_id: 'EM-01.02.01'
  tag gtitle: 'EM-01.02.01'
  tag fix_id: 'F-49140r769923_fix'
  tag 'documentable'
  tag legacy: ['V-30980', 'SV-41024r3_rule']
end

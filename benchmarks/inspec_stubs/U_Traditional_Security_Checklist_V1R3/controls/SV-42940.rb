control 'SV-42940' do
  title 'Sensitive Item Control - Keys, Locks and Access Cards Controlling Access to Information Systems (IS) or IS Assets Connected to the DISN'
  desc "Lack of an adequate key/credential/access device control could result in unauthorized personnel gaining access to the facility or systems with the intent to compromise classified information, steal equipment, or damage equipment or the facility.

REFERENCES:

UG 2040-SHR, User's Guide on Controlling Locks, Keys, and Access Cards and Best Practices – found on the DoD Lock Program site:
https://www.navfac.navy.mil/content/dam/navfac/Specialty%20Centers/Engineering%20and%20Expeditionary%20Warfare%20Center/DoD_Lock_Program/PDFs/UG-2040-SHR.pdf

DoD 5200.8-R Physical Security Program 
Chapter 2, para C2.1.4.4., C2.1.4.5., C2.1.4.8. and Chapter 3, para C3.3 and Pg 7, DL1.9 Personnel Identity Management and Protection 

DoD Manual 5200.08 Volume 3, Physical Security Program: Access to DoD Installations, 2 January 2019

DoD 5200.22-M (NISPOM), February 2006, Incorporating Change 2, May 18, 2016
Chapter 5, paragraphs 5-308, 5-310, 5-312, 5-313, 5-314 

NIST Special Publication 800-53 (SP 800-53) 
Controls: IA-5, SC-12, MA-5, PE-2, PE-3, PS-4, PS-5 

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), 9 February 2011 
Encl C, para 34. 

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information 
Encl3, para 6.e.(1) (2) and Appendix to Encl 3, para 3.a."
  desc 'check', '1. Check to ensure there are written procedures for the control of sensitive items such as keys, locks, badges and smart cards (CAC, token, or other locally issued badge).  

2. Check to verify the process is being followed and that it is effective.  As a minimum, lock and key systems or automated entry control systems (AECS) using coded access swipe/proximity badges - require a key or credential inventory, issuance records, and procedures for returning the key or access control credential once the user no longer needs it.  

3. Check to ensure a Key/Credential Control Officer and/or Key/Credential Custodians are appointed in writing to implement the system for controlling keys, locks and access control credentials.  

4. Check to ensure the Key/Credential Control Officer conducts at least an annual inventory/reconciliation of all keys/credentials issued and on-hand.

5. Check to ensure that all keys/credentials are also inventoried upon change of Key/Credential Control Officer or Key/Credential Custodian.

NOTE FOR REVIEWERs:
If the Combatant Command, Service or Agency (CC/S/A) has issued guidelines for control of sensitive items the inspected organization may be considered compliant if following the issued guidelines.
           
TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments.  Not applicable to a field/mobile environment.'
  desc 'fix', '1. Ensure there are written procedures for the control of sensitive items such as keys, locks, badges and smart cards.  

2. Verify the process for controlling keys/locks and credentials is being followed and that it is effective.  As a minimum, lock and key systems or access control systems (using coded access swipe/prox badges) require a key or credential inventory, issue records, and a procedure for returning the key or access control credential once the user no longer needs it.  

3. Ensure a Key Control/Credential Officer and/or Key/Credential Custodians are appointed in writing to implement the system for controlling keys, locks and access control credentials.  

4. Ensure the Key/Credential Control Officer conducts at least an annual inventory/reconciliation of all keys/credentials issued and on-hand.

5. Ensure that all keys/credentials are also inventoried upon change of Key/Credential Control Officer or Key/Credential Custodian.

NOTE:

If the organization’s Combatant Command, Service or Agency (CC/S/A) has issued guidelines for control of sensitive items, then compliance with this rule will be considered validated if following the issued guidelines.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-41042r6_chk'
  tag severity: 'medium'
  tag gid: 'V-32603'
  tag rid: 'SV-42940r3_rule'
  tag stig_id: 'PH-07.02.01'
  tag gtitle: 'Sensitive Item Control - Keys, Locks and Access Cards'
  tag fix_id: 'F-36518r4_fix'
  tag 'documentable'
end

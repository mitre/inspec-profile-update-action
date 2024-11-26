control 'SV-245794' do
  title 'Information Security (INFOSEC) - Safe/Vault/Secure Room Management'
  desc 'Lack of adequate or Improper procedures for management of safes/vaults and secure rooms could result in the loss or compromise of classified material.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl C, paragraphs 26.s.(5) and 34.c.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
MP-4 and PE-5

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 2, para 9; Encl 3, para 1.b, 1.d., 6.b., 6.d., 7., 8., 9., 10., 11., 13., and 14.

Information Security Oversight Office, 32 CFR Parts 2001 and 2003 Classified National Security Information; Final Rule: Subpart H - Standard Forms'
  desc 'check', %q(Check all safes, vaults and/or secure rooms (*only those containing DoDIN assets) for proper management practices:

1. Ensure only GSA-approved security containers are being utilized. GSA-approved security containers and vault doors must have a label indicating "General Services Administration Approved Security Container," affixed to the front of the container. Usually this is on the control or the top drawer of safes.

2. Ensure combinations are changed as required. This is recorded on the applicable SF 700 form and must be done: When placed in service, When someone with knowledge of the combination departs (unless other sufficient controls exist to prevent that individual's access to the lock), When compromise of the combination is suspected, or When taken out of service,  built-in combination locks shall be reset to the standard combination of 50-25-50.

3. Ensure forms SF 700, Security Container Information are properly completed for each safe, vault and secure room used to store classified DISN assets. The SF 700 is a two-part form consisting of an envelope with a tear-off tab and cover sheet. The cover sheet and face of the envelope (Part 1 of the form) provide space for information about the activity, container, type of lock, and who to contact if the container is left open. Required checks follow. Ensure the SF 700: 

  a. Shows the location of the door or container.

  b. Reflects the names, home addresses, and home telephone numbers of the individuals having knowledge of the combination who are to be contacted in the event that the vault, secure room, or container is found open and unattended.

  c. Part 1 of SF 700 is not classified, but contains personally identifiable information (PII) that shall be protected by sealing Part 1 in an opaque envelope (not provided as part of the SF 700) conspicuously marked "Security Container Information" and stored in accordance with SF 700 instructions. NOTE: If the information must be accessed during non-duty hours and a new opaque envelope is not available to replace the opened one, the original envelope should be temporarily resealed, to the extent possible, until Part 1 can be placed in a new envelope the next working day.

  d. After the cover sheet (Part 1) is filled out and sealed in an opaque envelope, attach it to the inside of the control drawer or on the inside face of the vault or secure room door, with either tape or a magnetically-attached holder.

  e. The tear-off tab (Part 2) with the combination record is placed in the envelope provided with the form, sealed, properly marked with the classification level and stored by the security manager in another approved classified container.

4. Ensure forms SF 702, Security Container Check Sheet are properly completed for each safe, vault and secure room used to store classified DISN assets. Following are required checks for the SF 702 form. Ensure:
 
  a. It provides a record of the names and times that persons have opened, closed or checked a particular container (safe, vault or secure room) that holds classified information.

  b. It is properly annotated to reflect each opening and closing of the container.

  c. It is properly annotated to reflect (at least) daily checks of ALL containers - whenever an area housing the containers is entered/occupied - EVEN IF THE CONTAINER IS NOT OPENED. If on weekends or holidays the area housing the container is not occupied the SF 702 would not require annotation; however, in the event the area is accessed for even a short period of time, the SF 702 forms for each container in the area should be annotated to reflect the container was checked. Annotation of the SF 702 forms should be conducted IN ADDITION TO the annotation of SF 701 forms reflecting end-of-day checks.

NOTE: If CC/S/A INFOSEC implementing instructions contain specific guidance in contradiction to the above DoDIN SF 702 requirements/checks then the CC/S/A guidance may be followed. Failure to comply with either the above guidance or CC/S/A documented guidance will result in a finding of non-compliance.

5. Ensure container repairs are conducted correctly IAW FED-STD-809. Details are at the DoD Lock Program WEB Portal for Drawer head Replacement.

TACTICAL ENVIRONMENT: This check is applicable where safes, vaults or secure rooms are used to protect classified materials or systems. The only exception will be for urgent (short term) tactical operations or other contingency situations where fixed facilities and equipment are not yet present or incapable of being used.)
  desc 'fix', %q(All safes, vaults and/or secure rooms containing SIPRNet assets must adhere to the following proper management practices:

1. Only GSA-approved security containers are utilized. GSA-approved security containers and vault doors must have a label indicating "General Services Administration Approved Security Container," affixed to the front of the container, usually this is on the control or the top drawer of safes.

2. Combinations must be changed as required. This is recorded on the applicable SF 700 form and must be done: When placed in service, When someone with knowledge of the combination departs (unless other sufficient controls exist to prevent that individual's access to the lock), When compromise of the combination is suspected, or When taken out of service built-in combination locks shall be reset to the standard combination of 50-25-50.

3. Standard Forms (SF) 700, Security Container Information and SF 702, Security Container Check Sheet must be properly completed and maintained.

4. Repairs must be conducted correctly IAW FED-STD-809. Details are at the DoD Lock Program WEB Portal for Drawer head Replacement.)
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49225r770042_chk'
  tag severity: 'medium'
  tag gid: 'V-245794'
  tag rid: 'SV-245794r770044_rule'
  tag stig_id: 'IS-01.02.01'
  tag gtitle: 'IS-01.02.01'
  tag fix_id: 'F-49180r770043_fix'
  tag 'documentable'
  tag legacy: ['V-31266', 'SV-41522r3_rule']
end

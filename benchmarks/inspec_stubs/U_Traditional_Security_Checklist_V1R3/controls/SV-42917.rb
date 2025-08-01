control 'SV-42917' do
  title 'Physical Protection of Unclassified Key System Devices/Computer Rooms in Large Processing Facilities'
  desc 'Allowing access to systems processing sensitive information by personnel without the need-to-know could permit loss, destruction of data or equipment or a denial of service. Loss could be accidental damage or intentional theft or sabotage.

REFERENCES:

DoD 5200.22-M (NISPOM), February 2006, Incorporating Change 2, May 18, 2016 
Chapter 8, IS Security

DoD 5200.8-R Physical Security Program 
Chapters 1, 2 and 3 

DoD Manual 5200.08 Volume 3, Physical Security Program: Access to DoD Installations, 
2 January 2019

NIST Special Publication 800-53 (SP 800-53) 
Controls: PE-2, PE-3, PE-4, PE-6 and PE-18 

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), 9 February 2011 
Encl C, para 34. 

DoDI 8500.01, Cybersecurity, March 14, 2014, Enclosure 2, paragraph 13.s.

DoD Manual 5200.01, Volume 4, February 24, 2012
SUBJECT: DoD Information Security Program: Controlled Unclassified Information (CUI)'
  desc 'check', '1. Check to ensure that Unclassified system assets (servers, DASD, tape drives, hubs, etc.) are protected in secure locked/access controlled rooms or closets and maintained separately from general employee access.

NOTE 1: This check concerns protection of "ONLY UNCLASSIFIED" System and Network Devices. 

NOTE 2: While not required; the ideal situation with larger computer systems is to locate all major system components within "raised floor" computer rooms.  Regardless of the location the key factor in determining acceptable security compliance is if the equipment is accessible only to properly vetted persons who require unescorted access to the equipment for performance of duties.  
   
NOTE 3: While not preferred, if space and/or size of the Information Systems (IS) assets do not allow for being housed in a secure room or closet they may be maintained in locked Information System (IS) cabinets that preclude ease of access by unauthorized individuals.   

2. Check to ensure that properly managed Automated Entry Control Systems (AECS), mechanical access devices such as cipher locks, or keyed locks are being used to control access to these rooms, closets or cabinets.  

NOTE 4: If keyed locks are used check to ensure that proper key control procedures are in place. *If key control procedures are determined to be inadequate a finding under this STIG rule should be written. 

TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments.  Not applicable to a field/mobile environment.'
  desc 'fix', '1. Ensure that Unclassified system assets (servers, DASD, tape drives, hubs, etc.) are protected in secure locked/access controlled rooms or closets and maintained separately from general employee access.

NOTE 1: This potential VUL concerns protection of "ONLY UNCLASSIFIED" System and Network Devices. 

NOTE 2: While not required; the ideal situation with larger computer systems is to locate all major system components within "raised floor" computer rooms.  Regardless of the location the key factor in determining acceptable compliance is if the equipment is accessible only to properly vetted persons who require unescorted access to the equipment for performance of duties.  
   
NOTE 3: While not preferred, if space and/or size of the Information Systems (IS) assets do not allow for being housed in a separate room or closet they may be maintained in locked Information System (IS) cabinets that preclude ease of access by unauthorized individuals.   

2. Ensure that properly managed Automated Entry Control Systems (AECS), mechanical access devices such as cipher locks, or keyed locks are being used to control access to these rooms, closets or cabinets.  

NOTE 4: If keyed locks are used, ensure that proper key control procedures are in place.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-41025r5_chk'
  tag severity: 'medium'
  tag gid: 'V-32580'
  tag rid: 'SV-42917r3_rule'
  tag stig_id: 'PH-03.02.01'
  tag gtitle: 'Physical Protection of Unclassified Key System Devices'
  tag fix_id: 'F-36507r3_fix'
  tag 'documentable'
end

control 'SV-41020' do
  title 'Protected Distribution System (PDS) Monitoring - Daily (Visual) Checks'
  desc 'A PDS that is not inspected, monitored and maintained as required could result in undetected access, sabotage or tampering of the unencrypted transmission lines. This could directly lead to the loss or compromise of classified.

REFERENCES:    
                             
CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 35.c.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 4, paragraphs 5-402.c. and 5-403 

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 4, para 3.b. and 4.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-4, SC-7, SC-8, IR-4, and IR-6

CNSSI No. 7003, September 2015, Protected Distribution Systems (PDS), Section VIII, paragraphs 23.c. & 24., Section XI, paragraphs 31, 32, 33 and 34.a. (1) & (2) and Table 3. Visual Inspection Schedule.'
  desc 'check', 'A PDS carrying SIPRNet cable is subject to periodic visual inspections IAW (Table 3. Visual Inspection Schedule, of CNSSI 7003).  Check to ensure:
  
1. At least one daily inspection of the PDS line is conducted or more frequently if required by Table 3.  

2. A log is maintained of the PDS inspections. The log must contain the date of the inspection, the time of the inspection, the inspector’s name, and the inspector’s title. The log must be kept on record for a minimum of one year. 
 
3. Person(s) are formally appointed (in writing) to conduct the visual inspections.   

4. The person(s) appointed to accomplish the visual inspection are trained sufficiently to recognize physical changes in PDS including attempts at penetration and tampering. 

5. That visual PDS inspections as detailed in Table 3 are conducted 365 days a year. 

NOTES: 

Visual inspections are not absolutely required for portions of PDS traversing a Secret or higher CAA but may be required by the AO.

In a tactical environment periodic visual checks are not applicable for Continuously Viewed Carriers since they are under continuous observation, 24 hours per day (including when operational).  This check for visual inspections is only applicable to tactical environments where Hardened Carriers - versus Continuously Viewed Carriers - are used.'
  desc 'fix', 'A PDS carrying SIPRNet cable is subject to periodic visual inspections IAW (Table 3. Visual Inspection Schedule, of CNSSI 7003). To correct this finding visual checks of PDS must be completed on a continuing basis as follows:  

1. At least one daily inspection of the PDS line must be conducted, or more frequently if required by Table 3. 

2. A log must be maintained of the PDS inspections. The log must contain the date of the inspection, the time of the inspection, the inspector’s name, and the inspector’s title. The log must be kept on record for a minimum of one year. 

3. Person(s) must be formally appointed (in writing) to conduct the visual inspections. 

4. The person(s) appointed to accomplish the visual inspection must be trained sufficiently to recognize physical changes in PDS including attempts at penetration and tampering.

5. That visual PDS inspections as detailed in Table 3 are conducted 365 days a year.  

NOTES: 

Visual inspections are not absolutely required for portions of PDS traversing a Secret or higher CAA but may be required by the AO.

In a tactical environment periodic visual checks are not applicable for Continuously Viewed Carriers since they are under continuous observation, 24 hours per day (including when operational).  This check for visual inspections is only applicable to tactical environments where Hardened Carriers - versus Continuously Viewed Carriers - are used.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39639r7_chk'
  tag severity: 'medium'
  tag gid: 'V-30976'
  tag rid: 'SV-41020r3_rule'
  tag stig_id: 'CS-06.02.01'
  tag gtitle: 'PDS Monitoring - Daily Visual Checks'
  tag fix_id: 'F-34787r7_fix'
  tag 'documentable'
  tag severity_override_guidance: 'This finding may be lowered to a CAT III if checks are conducted and recorded but there is no roster or written appointment of who is to conduct the checks.'
end

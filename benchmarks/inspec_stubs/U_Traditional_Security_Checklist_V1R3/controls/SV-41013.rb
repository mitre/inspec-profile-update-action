control 'SV-41013' do
  title 'Protected Distribution System (PDS) Construction - Continuously Viewed Carrier'
  desc 'A PDS that is not constructed and configured as required could result in the undetected interception of classified information.  A continuously viewed PDS may not be in a physically hardened carrier and the primary means of protection is continuous observation and control of the unencrypted transmission line.  If not maintained under continuous observation an attacker (insider or external) could have an opportunity to tap and intercept unencrypted communications on the exposed cable.

REFERENCES:   
                            
CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 35.c.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 4, paragraphs 5-402.c. and 5-403  
 
DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 4, para 3.b. and 4.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-4, SC-7, and SC-8

CNSSI No. 7003, September 2015, Protected Distribution Systems (PDS), Section IV, paragraph 7. and Section X, paragraph 30.e.'
  desc 'check', 'Interior or Exterior PDS: Continuously viewed Carrier.  This is one of five types of Category 2 PDS allowed IAW the CNSSI 7003.   

Check to ensure:
 
1. The transmission line is under continuous observation, 24 hours per day, including when non-operational. (CAT I finding)
 
2. It is separated from all non-continuously viewed circuits ensuring an open field of view. (CAT III finding)

3. The carrier has an SOP that includes the requirement to investigate any attempt to disturb the PDS. The requirement must include that appropriate security personnel investigate the area of attempted penetration within 15 minutes of discovery. (CAT II finding)

4. The PDS is not located within an Uncontrolled Access Area (UAA).  (CAT I)'
  desc 'fix', 'Interior or Exterior PDS: Continuously viewed Carrier. This is one of five types of Category 2 PDS allowed IAW the CNSSI 7003. 

There are four requirements that must be met for this type of distribution system:
  
1. The transmission line must be under continuous observation, 24 hours per day (including when non-operational).

2. The transmission line must be separated from all non-continuously viewed circuits ensuring an open field of view.

3. There must be an SOP for those responsible for observation of the carrier that includes the requirement to investigate any attempt to disturb the PDS. The requirement must include that appropriate security personnel investigate the area of attempted penetration within 15 minutes of discovery.

4. The PDS must not be located within an Uncontrolled Access Area (UAA).'
  impact 0.7
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39632r10_chk'
  tag severity: 'high'
  tag gid: 'V-30971'
  tag rid: 'SV-41013r3_rule'
  tag stig_id: 'CS-04.01.06'
  tag gtitle: 'PDS Construction - Continuously Viewed Carrier'
  tag fix_id: 'F-34782r9_fix'
  tag 'documentable'
  tag severity_override_guidance: 'The default severity level is a Category I based on a transmission line not under continuous observation, 24 hours per day, including when operational.  (CAT I)

If it is determined that the unencrypted SIPRNet transmission cable is under proper continuous observation and control 24 hours per day, including when operational and the following is found to be the only discrepancy, the finding may be reduced as follows:

The carrier does not have an SOP that includes the requirement to investigate any attempt to disturb the PDS and/or the SOP does not include procedures for appropriate security personnel to investigate the area of attempted penetration within 15 minutes of discovery. (CAT II) 

The Continuously Viewed Carrier is not separated from all non-continuously viewed circuits ensuring an open field of view. (CAT III)'
  tag potential_impacts: 'There are five types of Category 2 PDS:  1. Hardened Carrier (STIG ID: CS-04.01.02) 2.  Alarmed Carrier (STIG ID: CS-04.01.08) 3.  Continuously Viewed Carrier. (STIG ID: CS-04.01.06)  4.  Buried Carrier (STIG ID: CS-04.01.04) and 5. Suspended Carrier (STIG ID: CS-04.01.05).

This Rule covering Continuously Viewed Carriers (STIG ID CS-04.01.06) may be used in conjunction with the other Category 2 carriers.  Different requirements apply to each type of Category 2 carrier and must be assessed under their respective STIG Rules.'
end

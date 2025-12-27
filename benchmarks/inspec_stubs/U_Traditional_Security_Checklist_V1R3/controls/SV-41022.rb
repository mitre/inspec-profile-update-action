control 'SV-41022' do
  title 'Protected Distribution System (PDS) Monitoring - Initial Inspection'
  desc 'A PDS that is not inspected, monitored and maintained as required could result in undetected access, sabotage or tampering of the unencrypted transmission lines. This could directly lead to the loss or compromise of classified.

REFERENCES:
                                 
CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 35.c.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 4, paragraphs 5-402.c. and 5-403
   
DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 4, para 3.b. and 4.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-4, SC-7, SC-8, IR-4, IR-6, and PE-19

CNSSI No. 7003, September 2015, Protected Distribution Systems (PDS), Section IV, paragraph 10, and Section XI, paragraph 34.b. 2) a)'
  desc 'check', 'Check to ensure:

1. The PDS was inspected prior to initial operation.  Documentation of the inspection and results should be available for review. This meets the following requirement from the CNSSI 7003: "The Approval Authority (AO) must ensure PDS are inspected in accordance with SECTION XI and certified prior to initial operation."

2. The initial inspection was a technical inspection performed by a trained CTTA prior to approval of the PDS by the AO.

3. The initial inspection documented the path of the PDS, the locations for all pull boxes, and the locations for all conduit joints at intervals less than the length of conduit segments (typically 10 feet).

NOTES: 

1. The PDS may be documented using detailed “as-built” installation drawings or photographs. *Subsequent technical inspections can then verify the path of the PDS and the location of pull boxes and joints.

2. When test equipment is locally available and resident expertise allows, the initial inspection should measure and record the electrical characteristics of the PDS lines to obtain a baseline electrical profile of the PDS.
 
3. Such measurements may consist of signal levels, voltage levels, time domain reflectometer (TDR) recorded readings, and any other electrical measurements that may be recorded and retained. * Subsequent technical inspections may then record and compare measurements taken to the previously recorded baseline measurements to identify possible tampering attempts.

4. This check is applicable in a tactical environment if the PDS is located within a fixed facility.  It is not applicable to field/mobile PDS.
  
5. In the reviewer notes be sure to provide the date of the initial inspection, name of inspector and general description of results.'
  desc 'fix', 'Following is a reiteration of the requirement:
 
1. The PDS must be inspected prior to initial operation.  Documentation of the inspection and results must be available for review.  This meets the following requirement from the CNSSI 7003: "The Approval Authority (AO) shall ensure PDS are inspected in accordance with SECTION XI and certified prior to initial operation."

2. The initial inspection must be a technical inspection performed by a trained CTTA prior to approval of the PDS by the AO.

3. The initial inspection must document the path of the PDS, the locations for all pull boxes, and the locations for all conduit joints at intervals less than the length of conduit segments (typically 10 feet).
 
NOTES:

1. The PDS may be documented using detailed “as-built” installation drawings or photographs. *Subsequent technical inspections can then verify the path of the PDS and the location of pull boxes and joints.

2. When test equipment is locally available and resident expertise allows, the initial inspection should measure and record the electrical characteristics of the PDS lines to obtain a baseline electrical profile of the PDS.
 
3. Such measurements may consist of signal levels, voltage levels, time domain reflectometer (TDR) recorded readings, and any other electrical measurements that may be recorded and retained. * Subsequent technical inspections may then record and compare measurements taken to the previously recorded baseline measurements to identify possible tampering attempts.

4. This check is applicable in a tactical environment if the PDS is located within a fixed facility.  It is not applicable to field/mobile PDS.
  
5. In the reviewer notes be sure to provide the date of the initial inspection, name of inspector and general description of results.

6. Obviously an initial inspection cannot ever be conducted once it is not completed.  Therefore the fix for this finding is to send a written request to the PDS approval authority asking for an "initial" inspection of the PDS by an individual appointed by the approval authority. If the approval authority concurs to conduct the inspection then this finding can be closed once the inspection is actually completed and any results form that inspection are closed.  If the reply from the approval authority indicates they will not complete their "required" inspection then then finding can be closed and the reply from the approval authority should be maintained for future reference.'
  impact 0.3
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39641r9_chk'
  tag severity: 'low'
  tag gid: 'V-30978'
  tag rid: 'SV-41022r3_rule'
  tag stig_id: 'CS-06.03.02'
  tag gtitle: 'PDS Monitoring - Initial Inspection'
  tag fix_id: 'F-34789r8_fix'
  tag 'documentable'
end

control 'SV-41025' do
  title 'TEMPEST - Red/Black separation (Processors)'
  desc 'Failure to maintain proper separation could result in detectable emanations of classified information.

REFERENCES:  
                               
CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND)

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 11
 
NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: PE-19 & PE-19(1)

Committee on National Security Systems Policy 300, “National Policy on Control of Compromising Emanations,” April 2004, as amended  
                              
Committee on National Security Systems Instruction 7000, “TEMPEST Countermeasures for Facilities,” May 2004, as amended    
                           
DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014
                                    
CNSSAM TEMPEST/ 1-13, 17 January 2014, RED/BLACK Installation Guidance'
  desc 'check', 'Check for minimum separation between any RED processor and BLACK equipment IAW the following guidance:

A separation distance of 1 meter (39 inches) shall be provided between RED equipment and:

1. BLACK wirelines that connect to RF transmitters; and

2. BLACK equipment with lines that connect to RF transmitters.

A separation distance of 30 cm (12 inches) shall be provided between RED Equipment and BLACK wirelines that directly leave the inspectable space. 

NOTES: 
 
1. This requirement is applicable in a tactical environment. 
 
2. The supporting Certified TEMPEST Technical Authority (CTTA) should always be contacted for specific separation requirements, which may be greater than the distance reflected in this check.

3. Inspectable Space is the three dimensional space surrounding equipment that processes classified and/or sensitive information within which TEMPEST exploitation is not considered practical or where legal authority to identify and remove a potential TEMPEST exploitation exists and is exercised. CTTAs have the authority to define the inspectable space.'
  desc 'fix', 'A separation distance of 1 meter (39 inches) shall be provided between RED equipment and:

1. BLACK wirelines that connect to RF transmitters; and

2. BLACK equipment with lines that connect to RF transmitters.

A separation distance of 30 cm (12 inches) shall be provided between RED Equipment and BLACK wirelines that directly leave the inspectable space. 

NOTES:
  
1. This requirement is applicable in a tactical environment.  

2. The supporting CTTA should always be contacted for specific separation requirements, which may be greater than the distance reflected in this check.

3. Inspectable Space is the three dimensional space surrounding equipment that processes classified and/or sensitive information within which TEMPEST exploitation is not considered practical or where legal authority to identify and remove a potential TEMPEST exploitation exists and is exercised. CTTAs have the authority to define the inspectable space.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39646r9_chk'
  tag severity: 'medium'
  tag gid: 'V-30981'
  tag rid: 'SV-41025r3_rule'
  tag stig_id: 'EM-02.02.01'
  tag gtitle: 'TEMPEST - Red/Black separation (Processors)'
  tag fix_id: 'F-34792r5_fix'
  tag 'documentable'
end

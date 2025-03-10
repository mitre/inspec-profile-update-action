control 'SV-40980' do
  title 'Protected Distribution System (PDS) Construction - Point of Presence (PoP) and Terminal Equipment Protection.  This requirement concerns security of both the starting and ending points for PDS within proper physically protected and access controlled environments.'
  desc 'A PDS that is not constructed and physically protected as required could result in the covert or undetected interception of classified information.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 35.c.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 4, paragraphs 5-402.c. and 5-403 
  
DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 4, para 3.b. and 4.a.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-4, SC-7, and SC-8
 
CNSSI No. 7003, September 2015, Protected Distribution Systems (PDS), Section IV, paragraph 7., Section VIII, paragraphs 22, 25, 26 & paragraph 27.b. & c. and Section X, paragraph 30.a.'
  desc 'check', 'This check concerns security requirements for the physical locations of both the starting and ending points for Protected Distribution Systems (PDS) within a physical enclave. 

Check to ensure: 
1. The PDS originates within the room or area containing the SIPRNet Point of Presence (PoP) for the facility or area, which must be in a Secret or above Secure Room, Vault, SCIF or alternatively in an Information Processing Systems (IPS) Container with SIPRNet connected equipment (router/switch/PC/laptop/multi-function device (e.g., printer, copier, fax)).  An IPS container is a specially designed safe for secured operation of classified network and end user equipment.   

2. PDS terminal equipment (wall jacks/ports) are located in a Secret or higher Controlled Access Area (CAA), Secret or higher vault, Secret or higher Secure Room or in a SCIF.

3. PDS terminating in areas not a Secret or higher CAA may alternatively terminate in an IPS Container with SIPRNet connected equipment (router/switch/PC/laptop/multi-function device (printer, copier, and fax)).  

4. If an IPS container is used to secure equipment at a PDS termination point, ensure it is located within at least a Limited Access Area (LAA).  *It cannot ever be located in an Uncontrolled Access Area (UAA).

5. In exceptional situations, when the PDS termination area cannot be access controlled to the level of the data carried by the PDS (e.g., in a multi-use conference room), ensure the PDS termination point (wall jack/port) is secured with a lock box. Access Controlled to the level of the data carried by the PDS for SIPRNet connections means the PDS termination area must minimally be a secret CAA.  The lock box must meet the same construction requirements as a pull box for the PDS carrier type.  *Specifications for pull boxes and termination lock boxes are covered in rule:  Protected Distribution System (PDS) Construction - Accessible Pull Box Security, STIG ID: CS-04.01.03, Rule ID: SV-41000r3_rule Vuln ID: V-30958.  A finding for deficient pull box or termination lock box construction should be cited under STIG ID: CS-04.01.03.

6. If a lock box is used to secure a PDS termination/end point (wall jack/port), ensure it is located within at least a Limited Access Area (LAA).  *It cannot ever be located in an Uncontrolled Access Area (UAA).

7. PDS lock boxes located within a LAA are physically disconnected (cables pulled) from equipment and the lock boxes secured with an approved PDS lock when the lock box is not under the continuous observation and control of a properly cleared person (secret security clearance for SIPRNet).
  
NOTES: 

Access to all PDS points with breakouts must be restricted to personnel cleared at the highest level of the breakout and therefore, the PDS terminal equipment (end point) must either be locked or continuously safeguarded by cleared persons to prevent tampering.

The S&G 8077 changeable combination padlock is the DoD standard/required PDS lock for user termination lock boxes that are opened/closed on a routine or frequent basis.  Tamper evident locks (keyed padlocks with seals) are not permitted to be used within the DoD, per guidance from USD(I) Policy.'
  desc 'fix', 'This fix concerns security requirements for the physical locations of both the starting and ending points for Protected Distribution Systems (PDS) within a physical enclave. 

All of the following requirements must be met:

1. The PDS must originate within the room or area containing the SIPRNet Point of Presence (PoP) for the facility or area, which must be in a Secret or above Secure Room, Vault, SCIF or alternatively in an Information Processing Systems (IPS) Container with SIPRNet connected equipment (router/switch/PC/laptop/multi-function device (e.g., printer, copier, fax)).  An IPS container is a specially designed safe for secured operation of classified network and end user equipment.
   
2. PDS terminal equipment (wall jacks/ports) must be located in a Secret or higher Controlled Access Area (CAA), Secret or higher vault, Secret or higher Secure Room or in a SCIF.

3. PDS terminating in areas not a Secret or higher CAA (SCAA) may alternatively terminate in an IPS Container with SIPRNet connected equipment (router/switch/PC/laptop/multi-function device (printer, copier, and fax)).
  
4. If an IPS container is used to secure equipment at a PDS termination point, it must be located within at least a Limited Access Area (LAA).  *It cannot ever be located in an Uncontrolled Access Area (UAA).

5. In exceptional situations, when the PDS termination area cannot be access controlled to the level of the data carried by the PDS (e.g., in a multi-use conference room), the PDS termination point (wall jack/port) must be secured with a lock box. Access Controlled to the level of the data carried by the PDS for SIPRNet connections means the PDS termination area must minimally be a secret CAA (SCAA).  The lock box must meet the same construction requirements as a pull box for the PDS carrier type.  *Specifications for pull boxes and termination lock boxes are covered in rule:  Protected Distribution System (PDS) Construction - Accessible Pull Box Security, STIG ID: CS-04.01.03, Rule ID: SV-41000r3_rule Vuln ID: V-30958.  A finding for deficient pull box or termination lock box construction should be cited under STIG ID: CS-04.01.03.

6.  If a lock box is used to secure a PDS termination/end point (wall jack/port), it must be located within at least a Limited Access Area (LAA).  *It cannot ever be located in an Uncontrolled Access Area (UAA).

7.  PDS lock boxes located within a LAA must be physically disconnected (cables pulled) from equipment and the lock boxes secured with an approved PDS lock when the lock box is not under the continuous observation and control of a properly cleared person (secret security clearance for SIPRNet). 

NOTES: 

Access to all PDS points with breakouts must be restricted to personnel cleared at the highest level of the breakout and therefore, the PDS terminal equipment (end point) must either be locked or continuously safeguarded by cleared persons to prevent tampering.

The S&G 8077 changeable combination padlock is the DoD standard/required PDS lock for user termination lock boxes that are opened/closed on a routine or frequent basis.  Tamper evident locks (keyed padlocks with seals) are not permitted to be used within the DoD, per guidance from USD (I) Policy.'
  impact 0.7
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39598r13_chk'
  tag severity: 'high'
  tag gid: 'V-30938'
  tag rid: 'SV-40980r4_rule'
  tag stig_id: 'CS-04.01.01'
  tag gtitle: 'PDS Construction - PoP and Terminal Equipment Protection'
  tag fix_id: 'F-34749r11_fix'
  tag 'documentable'
end

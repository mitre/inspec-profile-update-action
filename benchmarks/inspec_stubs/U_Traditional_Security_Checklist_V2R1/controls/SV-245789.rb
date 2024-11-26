control 'SV-245789' do
  title 'Information Assurance - Network Connections - Wall Jack Security on Classified Networks (SIPRNet or other Inspected Classified Network or System) Where Port Authentication Using IEEE 802.1X IS NOT Implemented'
  desc "Following is a summary of the primary requirement to use the IEEE 802.1X authentication protocol to secure SIPRNet ports (AKA: wall jacks) , which is covered in the Network STIG:

802.1X authentication involves three parties: a supplicant, an authenticator, and an authentication server. The supplicant is a client device (such as a laptop) that wishes to attach to the LAN/WLAN. The term 'supplicant' is also used interchangeably to refer to the software running on the client that provides credentials to the authenticator. The authenticator is a network device, such as an Ethernet switch or wireless access point; and the authentication server is typically a host running software supporting the RADIUS and EAP protocols. In some cases, the authentication server software may be running on the authenticator hardware. 

The authenticator acts like a security guard to a protected network. The supplicant (i.e., client device) is not allowed access through the authenticator to the protected side of the network until the supplicant's identity has been validated and authorized. With 802.1X port-based authentication, the supplicant provides credentials, such as user name/password or digital certificate, to the authenticator, and the authenticator forwards the credentials to the authentication server for verification. If the authentication server determines the credentials are valid, the supplicant (client device) is allowed to access resources located on the protected side of the network.

The requirements in this Traditional Security STIG rule serve as physical security mitigations for the lack of proper SIPRNet port security using IEEE 802.1X.  It is in essence a supplement to the Network STIG and provides the details for required mitigations. 

Network connections that are not properly protected are highly vulnerable to unauthorized access, resulting in the loss or compromise of classified or sensitive information.

REFERENCES:

Network Infrastructure Security Technical Implementation Guide (STIG)

Access Control in Support of Information Systems Security STIG (Access Control STIG)

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl C, paragraph 34.c.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
SC-8, PE-4 & PE-18

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 3, Appendix to Encl 3, and Encl 7

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 8 
 
DoD Instruction 8510.01, SUBJECT: Risk Management Framework (RMF) for DoD Information Technology (IT)

DoD Instruction 8500.01, SUBJECT: Cybersecurity

CJCSI 6211.02D, DEFENSE INFORMATION SYSTEMS NETWORK (DISN) RESPONSIBILITIES

CNSSP No.29, May 2013, National Secret Enclave Connection Policy"
  desc 'check', 'At sites where port authentication using 802.1X is not implemented check during your walk around to see if all SIPRNet wall jacks are secured in the proper manner.  The wall jacks can:
  
1. be located within a Secret or higher vault or Secret or higher Secure Room (open storage area), or a SCIF. 

2. be under the continuous observation of a cleared individual.   

3. be secured by a Hoffman or similar lock box with a GSA approved three position changeable combination padlock. Currently the ONLY lock meeting this standard is the S&G 8077 changeable combination padlock.   

*Lock boxes must also have hasps attached in such a way as they cannot be removed without force.  Using rivets, welds, etc. is acceptable. Also hinges must not be exposed - or be peened or welded in such a manner as to preclude removal without using detectable force. Electrical type boxes with pre-punch holes for conduit or cable cannot be used - even if the holes are not removed.  

4. be disabled at the end of each work day. This can ONLY be accomplished by a physical disconnect of the transmission cable at the classified circuit (SIPRNet) Point of Presence (PoP).  The PoP must be in an appropriate Secret or higher vault, secure room or SCIF. 

DETAILED EXPLANATION FOLLOWS:

1. The primary and most basic requirement (IAW the Network Policy found in the Layer 2 Switch STIG - Cisco) is implementation of IEEE port authentication standard 802.1X (logical software based port security) - regardless of the physical area or space in which the wall jacks/ports are located. TRADITIONAL SECURITY REVIEWERS MUST FIRST CHECK WITH THE NETWORK REVIEWER to determine if 802.1X has been properly implemented on SIPRNet before evaluating the physical security of SIPRNet Wall Jacks. * Do this early in your site visit so that wall jack physical security considerations can be properly evaluated during your site tour/walk around.

2. Not using 802.1X based port authentication on SIPRNet is a CAT I *Network STIG" finding, separate from any traditional security considerations. However, if 802.1X is not implemented there is another software based alternative, which is the Network STIG requirement to allow for "legacy" port security via MAC address. Several caveats go with this alternative and this is when the physical security mitigations are required to be implemented:  

    a. Use of simple MAC port security rather than 802.1X will result in a CAT III (*Network STIG) finding (on NIPRNet or SIPRNet). While this is not a traditional security check, it is something to be aware of.

    b. If simple MAC port security rather than 802.1X is implemented *on SIPRNet* (OR IF THERE IS ABSOLUTELY NO LOGICAL SOFTWARE BASED PORT SECURITY), the traditional security considerations and mitigations required IAW the Access Control STIG are as follows:  

       (1) If the wall jacks/drops/ports are located within spaces properly established as Secret or TS vaults or Secret or TS Secure Rooms (AKA: Collateral Classified Open Storage Areas) OR within an approved SCIF, then there is no requirement for supplemental physical security measures.  Again - No supplemental physical security controls are required for SIPRNet wall jacks in these areas.  

     (2) If the wall jacks are not located in Secret or higher secure room/vault/SCIF, the following physical security controls must be in place:

          (a) SIPRNet wall jacks must be secured *when not attended by persons with Secret or higher clearance* by a properly constructed lock box (Hoffman or similar commercial product or locally fabricated). The lock box must be 18-gauge steel or better and have no exposed or removable hinges (internal hinges are ideal). If used, external hinge pins must be peened, welded, etc. so they cannot be removed without evidence of forced removal. Hasp hardware must be riveted to the box or otherwise installed so that removal will require physical breaking of the box or hasp, thereby leaving evidence of actual or attempted entry. No pre-punch (knock-out) holes are allowed in the box. The lock box must be secured with a 3-position high security combination padlock (IAW the NSTISSI 7003 standard for PDS "Pull Boxes"). The S&G 8077 combination padlock is the ONLY existing combo padlock meeting this standard. See the DoD Lock Program site for details: 

https://portal.navfac.navy.mil/portal/page/portal/navfac/navfac_ww_pp/navfac_nfesc_pp/locks/CM_LOCKS/CL_PADLOCK/TAB_PADLOCK_PROD

          (b) If lock boxes are not used the alternative is to physically disconnect the hot SIPRNet transmission lines at the SIPRNet Point of Presence (PoP) after normal duty hours. The PoP must be located within a proper Secret or higher secure room or vault or SCIF.

NOTE 1: To reiterate the basic requirement: If IEEE 802.1X is properly implemented at the switch to authenticate devices *with clients (such as user work stations)* no additional supplemental physical security controls are required for the wall jacks. VERIFICATION FOR 802.1X IMPLEMENTATION MUST BE COORDINATED WITH THE NETWORK REVIEWER.

NOTE 2: Regardless of Port Authentication using IEEE 802.1X, *clientless devices (such as printers, scanners or multi-functional devices (MFD)* cannot be authenticated - but this should not cause an issue with needing supplemental physical controls (lock box or disconnect at PoP). The reason is because clientless devices like these that are connected to SIPRNet should "normally" be maintained in a Secret/TS secure room or vault or SCIF and therefore would not require supplemental physical security of the wall jacks.  Otherwise, MFD wall jacks must be protected by lock boxes or physical disconnect at the PoP after normal duty hours. Additional physical security measures or procedures for protection of classified MFD hard drives, residual images and printed materials will also be required, but these considerations are addressed elsewhere on the checklist. 

NOTE 3: Do not confuse the STIG wall jack lock box requirement with the CNSSI 7003 lock box requirement on the physical end point (Termination Boxes) of a Protected Distribution System (PDS). The reference for PDS is the CNSSI 7003, not the Access Control STIG. The requirements for PDS (pull-boxes, Access Points or Termination Boxes) and wall jack (lock boxes) are totally separate and unique, although it is possible to find the end of a PDS terminating in a lock box - that ALSO fulfills the requirement for protection of a wall jack where 802.1X is not implemented.  

NOTE 4: If there is no "legacy" MAC port security in place  there will be a CAT I port security finding written by the Network reviewer. If the traditional security reviewer also finds a CAT I finding for lack of physical security protective measures there is a CCRI scoring over ride that will decrease the OVERALL CCRI score. So where there is absolutely no logical or physical port/wall jack security in place - the result is very severe in terms of the CCRI score. Traditional Security reviewers, Network Reviewers (and Team Leads) need to be aware of this because of its significance to the site being reviewed. 
 
NOTE 5: TACTICAL ENVIRONMENT APPLICABILITY: The check is applicable for fixed facility tactical processing environments. Not applicable to a field/mobile environment.'
  desc 'fix', 'Where port authentication using IEEE 802.1X is not implemented, all SIPRNet wall jacks must be physically secured in the proper manner. The physical security mitigation for Wall Jacks not protected by 802.1X must use one of the following compensatory measures: 

1.SIPRNet connected Wall Jacks must be located within a Secret or higher vault or Secret or higher Secure Room (open storage area), or a SCIF. 

2. SIPRNet connected Wall Jacks must be under the continuous observation of a cleared individual. 

3. SIPRNet connected Wall Jacks must be secured by a Hoffman or similar lock box with a GSA approved three position changeable combination padlock. Currently the ONLY lock meeting this standard is the S&G 8077 changeable combination padlock. Lock boxes must also have hasps attached in such a way as they cannot be removed without force. Using rivets, welds, etc. is acceptable. Also hinges must not be exposed - or be peened or welded in such a manner as to preclude removal without using detectable force. Electrical type boxes with pre-punch holes for conduit or cable cannot be used - even if the pre-punch holes are not removed. 

4. SIPRNet connected Wall Jacks must be disabled at the end of each work day. This can ONLY be accomplished by a physical disconnect of the transmission cable at the classified circuit (SIPRNet) Point of Presence (PoP). The PoP must be located in an appropriate Secret or higher vault, secure room or SCIF.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49220r770027_chk'
  tag severity: 'high'
  tag gid: 'V-245789'
  tag rid: 'SV-245789r770029_rule'
  tag stig_id: 'IA-12.01.02'
  tag gtitle: 'IA-12.01.02'
  tag fix_id: 'F-49175r770028_fix'
  tag 'documentable'
  tag legacy: ['V-31171', 'SV-41344r3_rule']
end

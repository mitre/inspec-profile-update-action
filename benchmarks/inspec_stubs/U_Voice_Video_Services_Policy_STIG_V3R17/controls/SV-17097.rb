control 'SV-17097' do
  title 'A PC Communications Application is not tested for IA and Interoperability and are not listed on the DoD UC APL.'
  desc 'DoDI 8100.3 provides policy for the DoD that requires the testing and certification of telecommunications systems for Interoperability and Information Assurance (IA) while establishing an Approved Products List (APL) for certified and accredited products. Under Applicability and Scope, it states “This Instruction applies to the hardware or software for sending and receiving voice, data, or video signals across a network that provides customer voice, data, or video equipment access to the DSN, DRSN or PSTN.” Additional statements in this section expand this to most devices or systems that are associated with providing telecommunications service. 

The purpose of this testing is twofold. One aspect is to determine if a vendor’s product or system meets DoD functional requirements and that it can interoperate with established or existing DoD systems. The other aspect is to determine if the system can be configured to meet DoD IA requirements and operate at an acceptable level of risk. A product must be approved under both categories before listing on the APL.  

DoD components are required to fulfill their communications needs by only purchasing APL listed products, providing one of the listed products meets their needs. This means the APL must be consulted prior to purchasing a system or product. If no listed product meets the organization’s needs, they may sponsor a product for testing that does meet their needs. 

NOTE: The APL as created by this instruction was originally called the DSN APL and covered dial-up telecommunications systems or products providing unclassified communications. It has been expanded to cover additional types of approved products and has been renamed to the Unified Capabilities APL by the Office of the Assistant Secretary of Defense (OASD) for Networks and Information Integration (NII). Additional categories have been implemented for DRSN (classified communications) related systems/products and for IPv6 capable products. The APL can be found at http://jitc.fhu.disa.mil/apl/index.html. This APL is referred to as the DoD APL or UC APL. 

Tactical use cases or systems that do not provide access to the DSN, DRSN or PSTN which are private closed communications systems, may be accredited via the Information Support Plan (ISP) or Tailored Information Support Plan (TISP) process managed by the Office of the Secretary of Defense (OSD), Joint Staff J6I, and the Joint Interoperability Test Command (JITC) United States (US) Military Communications Electronics Board (USMCEB) Interoperability Test Panel (ITP). 

This policy applies directly to any PC communications application that provides voice communications services to and/or from the DSN, DRSN/VoSIP, or PSTN. This will most often be a soft-phone or unified communications application (with any associated accessories) that is associated with or supported by a DoD telephone system. The application may, or may not, provide additional communications services such as video, collaboration, or other unified communications services. This policy is extensible to other types of PC communications applications whose primary purpose may be VTC, IM, or collaboration, if the application or service provides interoperability with the DSN, DRSN/VoSIP, or PSTN typically through a gateway, or uses these systems for transport.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

Ensure PC communications applications providing voice, data, or video communications interoperability with the DSN, DRSN/VoSIP, or PSTN, along with any associated accessories (e.g., USB phones, cameras, and USB ATAs), are interoperability and IA tested and placed on the Approved Products List (APL) prior to purchase, per DoDI 8100.3.

NOTE : APL listing of soft-phone applications, and/or associated accessories, will be in association with, or part of, the listed VoIP telecommunications switch/system that supports the application. Other applications (VTC or collaboration) will be listed with their core service or system.

NOTE: This is not a finding in the event a PC communications application implementation and/or supporting system is not associated with, interoperable with, or connected to DSN, DRSN/VoSIP, or PSTN and is never expected to be.

NOTE: The DRSN is a custom and proprietary non-VoIP telephone system. It interoperates, to a degree, with a Defense Information System Network (DISN) VoIP telephone system/service on the Secret Internet Protocol Router Network (SIPRNet). This VoIP service is called VoSIP (see acronym discussion in the next note).  The discussion/requirement here applies to PC communications application associated with VoSIP that ultimately can interoperate with DRSN endpoints.  

NOTE: NSA defines VoSIP as Voice over Secure IP or regular (un-encrypted or encrypted) VoIP over any secure or classified IP LAN (i.e., local C-LAN) or WAN (e.g., SIPRNet or JWICS). In general, VoSIP employs encryption at Layer 1/Layer 2 applied to links between un-encrypted classified enclaves. The use of the acronym VoSIP for the DISN service and for instantiations on DoD component’s classified LANs leads to confusion between the service and the intentional meaning of the acronym. NSA defines a similar acronym, SVoIP, meaning Secure VoIP. This refers to end-to-end NSA type-1 encrypted VoIP media and possibly signaling streams that can traverse a network having a lower classification. This is similar in concept to the secure voice service provided by a STU or STE as well as SCIP based devices. SCIP works at Layer 7 (application layer) and can use Type 1 or Type 3 encryption. It is not IP specific since it was developed for traditional fixed and mobile transport methods. Type 3 encryption of VoIP signaling and media is not SCIP. Unfortunately, the SVoIP acronym/term has also been corrupted by some organizations using it to refer to their implementation of VoIP on their classified LANs and the SIPRNet WAN.

Inspect the APL testing report for the APL approved VoIP system supporting the PC communications application to determine if it was tested and approved along with the supporting communications system. 

NOTE: these applications are typically NOT listed separately on the APL. APL testing reports are available to DoD users of the product and reviewers via email from the Unified Capabilities Certification Office (UCCO) at ucco@disa.mil. It is highly recommended that requests for these reports are submitted and the report obtained before SRR trips commence. This is a finding if it is determined that the PC communications application was not tested and approved along with the supporting communications system.'
  desc 'fix', 'Ensure PC communications applications providing voice, data, or video communications interoperability with the DSN, DRSN/VoSIP, or PSTN, along with any associated accessories (e.g., USB phones, cameras, and USB ATAs), are interoperability and IA tested and placed on the Approved Products List (APL) prior to purchase, per DoDI 8100.3.

Only implement APL tested PC communications applications. If necessary contact the Unified Capabilities Certification Office (UCCO) to determine what course of action and testing submittals should be pursued.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17153r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16109'
  tag rid: 'SV-17097r1_rule'
  tag stig_id: 'VVoIP 1120 (GENERAL)'
  tag gtitle: 'Deficient C&A: PC Comm. App. DoD APL Certificatio'
  tag fix_id: 'F-16215r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'De-certification of the supporting communications system or service.'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
end

control 'SV-17086' do
  title 'A Call Center or Computer Telephony Integration (CTI) system using soft clients must be segregated into a protected enclave and limit traffic traversing the boundary.'
  desc 'UC soft clients may be used on a strategic LAN when associated with or part of a CTI application. Traditional computer telephony integration CTI encompasses the control of a telephone or telecommunications switch by a computer application. Interfaces have been developed to provide connection between the computer, typically a workstation, and the telephone or other terminal attached to the telephone switch, and possibly a special analog or TDM line going directly to the telephone switch. Applications are also developed to make use of these interfaces to integrate a data application with the telephone system. Sometimes the integration is as simple as being able to dial a number from the computer application or it could provide full control of the switch as in the case of an operator’s console. In these traditional scenarios, the voice stayed in a traditional telephone set and the data stayed on the computer with the exception of the control information. If the voice does enter the computer, it is sent directly to the sound card or converted to a sound file for storage and possible file transfer. The voice communication is not transmitted in real time via IP protocols. In contrast, modern day CTI is changing in that today the voice communications and control is being transmitted using IP protocols and the hardware interfaces and telephones are being replaced by computer applications. 

NOTE: the CTI systems discussed here are not unified communications applications although some of the features are similar. CTI systems generally have a special function and are not a general user application. These are typically Call Center or Help Desk applications. This type of CTI typically involves integration with a database application. In this scenario, where soft-phones are an integral part of the CTI system/application, implementation of separate voice and data zones could be detrimental to the proper functioning of the application. While separation requirements should be enforced if possible, they could be relaxed providing the general CTI requirement of treating the CTI system as an enclave is followed. A system such as this should have its own VoIP controller. If the system needs to communicate with systems outside the CTI system enclave, proper boundary protection must be provided. For example, since IP soft-phones are prevalent in today’s call center / helpdesk systems, such a system would require the ability to place and receive phone calls from outside the CTI enclave. Calls might leave and enter the enclave via VoIP or a TDM media gateway. The workstations and call center agents may also need to email and access the web. 

NOTE: we have established that a network supporting a CTI application must be segregated from the enclave and that this can be accomplished by maintaining a closed network or a segregated and access controlled sub-enclave having appropriate boundary protection.'
  desc 'check', 'Review the site documentation to confirm a Call Center or CTI system using soft clients must be segregated into a protected enclave and limit traffic traversing the boundary. When a Call Center / CTI system/application (e.g., call center, helpdesk, operators console, E911 system, etc.) using soft clients are approved for use in the strategic LAN, ensure the following: 
- The supporting network is configured as a closed enclave or a segregated and access controlled sub-enclave having appropriate boundary protection between it and the local general business LAN or external WAN.
- In the event the CTI application accesses resources outside this enclave and there is the potential of the application being compromised from external sources, the supporting network is configured to provide separate voice and data zones and maintains separation of voice and data traffic per the VoIP STIG if technically feasible (i.e., such separation does not break the CTI application or there is another compelling reason).
- The supporting network enclave and boundary protection is configured in substantial compliance with the Enclave, Network Infrastructure, and VoIP STIGs.
- The CTI application/enclave (e.g., a call center application) is supported by a dedicated VoIP controller.

If a Call Center or CTI system using soft clients is not segregated into a protected enclave and limit traffic traversing the boundary, this is a finding.'
  desc 'fix', 'Implement a Call Center or CTI system using soft clients to be segregated into a protected enclave and limit traffic traversing the boundary.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17142r2_chk'
  tag severity: 'medium'
  tag gid: 'V-16098'
  tag rid: 'SV-17086r2_rule'
  tag stig_id: 'VVoIP 1025'
  tag gtitle: 'VVoIP 1025'
  tag fix_id: 'F-16203r2_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
end

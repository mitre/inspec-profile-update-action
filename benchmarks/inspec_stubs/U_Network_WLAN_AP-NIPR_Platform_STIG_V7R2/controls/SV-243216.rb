control 'SV-243216' do
  title 'The site must conduct continuous wireless Intrusion Detection System (IDS) scanning.'
  desc 'DoD networks are at risk and DoD data could be compromised if wireless scanning is not conducted to identify unauthorized WLAN clients and access points connected to or attempting to connect to the network.

DoD Components must ensure that a Wireless Intrusion Detection System (WIDS) is implemented that allows for monitoring of WLAN activity and the detection of WLAN-related policy violations on all unclassified and classified DoD wired and wireless LANs. The WIDS must be implemented regardless of whether or not an authorized WLAN has been deployed.

The WIDS must be capable of monitoring IEEE 802.11 transmissions within all DoD LAN environments and detecting nearby unauthorized WLAN devices.

The WIDS is not required to monitor non-IEEE 802.11 transmissions.

The WIDS must continuously scan for and detect authorized and unauthorized WLAN activities 24 hours a day, 7 days a week.

Note: Exceptions to WIDS implementation criteria may be made by the AO for DoD wired and wireless LAN operating environments. This exception allows the AO to implement periodic scanning conducted by designated personnel using handheld scanners during walk-through assessments. Periodic scanning may be conducted as the alternative to the continuous scanning only in special circumstances, where it has been determined on a case-by-case basis that continuous scanning is either infeasible or unwarranted. The AO exception must be documented.

The "infeasible" criteria includes the following use case examples:
- It is not my building - This scenario means that for contractual or other similar reasons, the DoD component is not allowed to install a WIDS.
- There is no power or space is limited - This scenarios means that for space weight and power (SWAP) reasons, the addition of continuous scanning capabilities cannot be accomplished because it would exceeds SWAP availability. Power would also affect the decision to waive continuous scanning requirements if the entire LAN is only in operation periodically (e.g., the wired/wireless LAN is enabled on a vehicle that is only operating when the vehicle is being used for a specific operation).
- The exception for "Minimal Impact WLAN Systems" that do not provide connectivity to WLAN-enabled PEDs (e.g., backhaul systems), have no available FIPS 140 validated 802.1X EAP-TLS supplicant, support a very small number of users for a specific mission (e.g., 10 or less users), are standalone networks, or are highly specialized WLAN systems that are isolated from the DODIN (e.g., handheld personal digital assistants [PDAs] used as radio-frequency identification [RFID] readers, a network of WLAN-enabled Voice over Internet Protocol [VoIP] phones) allows the AO to waive any of the security requirements in the Instruction. This includes using non-standard/proprietary FIPS-validated encryption, using an alternative FIPS-validated EAP type, and not having a continuous WIDS.
- The cost of the continuous WIDS capability is more expensive that the total cost of the LAN without a WIDS.

The AO must conduct a wireless threat risk assessment where analysis has shown that the threat environment is extremely unlikely to non-existent to meet the "unwarranted" exception criteria.'
  desc 'check', 'Interview the site ISSO. Determine if the scanning by a WIDS is being conducted and if it is continuous or periodic.

If a continuous scanning WIDS is used, there is no finding. 

If periodic scanning is used, verify the exception to policy is documented and signed by the AO. Verify the exception meets one of the required criteria.

If periodic scanning is being performed but requirements have not been met, this is a finding.

If no WIDS scanning is being performed at the site, this is a finding.'
  desc 'fix', 'Perform required WIDS scanning.'
  impact 0.5
  ref 'DPMS Target Network WLAN AP-NIPR Platform'
  tag check_id: 'C-46491r720101_chk'
  tag severity: 'medium'
  tag gid: 'V-243216'
  tag rid: 'SV-243216r720103_rule'
  tag stig_id: 'WLAN-NW-000100'
  tag gtitle: 'SRG-NET-000383'
  tag fix_id: 'F-46448r720102_fix'
  tag 'documentable'
  tag cci: ['CCI-002686']
  tag nist: ['SI-4 (23)']
end

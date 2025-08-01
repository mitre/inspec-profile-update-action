control 'SRG-NET-000391-CLD-000220_rule' do
  title 'The Mission Owner of the IaaS must continuously monitor outbound communications to other systems and enclaves for unusual or unauthorized activities or conditions.'
  desc 'Evidence of malicious code is used to identify potentially compromised information systems or information system components.

Unusual/unauthorized activities or conditions related to outbound communications traffic include, for example, internal traffic that indicates the presence of malicious code within organizational information systems or propagating among system components, the unauthorized exporting of information, or signaling to external information systems. 

Anomalies within organizational information systems include, for example, large file transfers, long-time persistent connections, unusual protocols and ports in use, and attempted communications with suspected malicious external addresses.


This function may be deployed within the cloud service environment, the MeetMe Point, cloud access point, or supporting Core Data Center (CDC).'
  desc 'check', "If this is a SaaS, this is not applicable.

Inspect the firewall and/or IDPS ACLs and filtering rules that filter traffic on any outbound interface from the IaaS's and systems. Verify these rules are configured for continuous monitoring. Verify the ACLs and security rules include rules and ACLs that detect and filter unusual or unauthorized activities or conditions such as large file transfers, persistent connections, unusual protocols and ports in use, communication with unauthorized entities, or other unusually high traffic from particular segments or devices.

If the IaaS/PaaS does not continuously monitor outbound communications to other enclaves and systems for unusual or unauthorized activities or conditions, this is a finding."
  desc 'fix', 'This applies to all Impact Levels. 
FedRAMP Moderate, High.

Configure the firewall and/or IDPS for continuous monitoring of all communications outbound from the virtual IaaS or PaaS.

Configure any ACLS and filtering rules on outbound interfaces to detect and filter unusual or unauthorized activities or conditions such as large file transfers, persistent connections, unusual protocols and ports in use, communication with unauthorized entities, or other unusually high traffic from particular segments or devices.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000391-CLD-000220_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000391-CLD-000220'
  tag rid: 'SRG-NET-000391-CLD-000220_rule'
  tag stig_id: 'SRG-NET-000391-CLD-000220'
  tag gtitle: 'SRG-NET-000391-CLD-000220'
  tag fix_id: 'F-SRG-NET-000391-CLD-000220_fix'
  tag 'documentable'
  tag cci: ['CCI-002662']
  tag nist: ['SI-4 (4) (b)']
end

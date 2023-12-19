control 'SRG-NET-000390-CLD-000210_rule' do
  title 'The Mission Owner of the IaaS or PaaS must continuously monitor and protect inbound communications from external systems, other IaaS within the same cloud service environment, or collocated mission applications for unusual or unauthorized activities or conditions.'
  desc 'Evidence of malicious code is used to identify potentially compromised information systems or information system components. 

Unusual/unauthorized activities or conditions related to information system inbound communications traffic include, for example, internal traffic that indicates the presence of malicious code within organizational information systems or propagating among system components, the unauthorized exporting of information, or signaling to external information systems. 

Anomalies within organizational information systems include, for example, large file transfers, long-time persistent connections, unusual protocols and ports in use, and attempted communications with suspected malicious external addresses.

This function may be deployed within the cloud service environment cloud access point or supporting Core Data Center (CDC).'
  desc 'check', 'If this is a SaaS, this is not applicable.

Inspect the Firewall and/or IDPS ACLs and filters on the firewall inbound interfaces. Verify these rules are configured for continuous monitoring. Verify the ACLs and security rules include rules and ACLs that detect and filter unusual or unauthorized activities or conditions such as large file transfers, persistent connections, unusual protocols and ports in use, communication with unauthorized entities, or unusually high traffic from particular segments or devices.

If the IaaS/PaaS does not continuously monitor inbound communications from external systems, other IaaS, or collocated mission applications within the same cloud service environment for unusual or unauthorized activities or conditions, this is a finding.'
  desc 'fix', 'This applies to all Impact Levels.
FedRAMP Moderate, High.

Configure the firewall and/or IDPS for continuous monitoring of all communications inbound to the virtual IaaS or PaaS.

Configure the ACLs and security rules to detect and filter unusual or unauthorized activities or conditions such as large file transfers, persistent connections, unusual protocols and ports in use, communication with unauthorized entities, or unusually high traffic from particular segments or devices.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000390-CLD-000210_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000390-CLD-000210'
  tag rid: 'SRG-NET-000390-CLD-000210_rule'
  tag stig_id: 'SRG-NET-000390-CLD-000210'
  tag gtitle: 'SRG-NET-000390-CLD-000210'
  tag fix_id: 'F-SRG-NET-000390-CLD-000210_fix'
  tag 'documentable'
  tag cci: ['CCI-002661']
  tag nist: ['SI-4 (4) (b)']
end

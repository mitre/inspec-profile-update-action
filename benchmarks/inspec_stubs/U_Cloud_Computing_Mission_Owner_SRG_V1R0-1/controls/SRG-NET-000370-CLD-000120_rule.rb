control 'SRG-NET-000370-CLD-000120_rule' do
  title 'The IaaS/PaaS/SaaS must register the service/application with the DOD allowlist for both internet-facing, inbound and outbound traffic.'
  desc 'Register the service/application with the DOD DMZ Whitelist for both inbound and outbound traffic if traffic will cross the IAPs. 

Utilizing a allowlist provides a configuration management method for allowing the execution of only authorized software, ports, protocols, and guest VMs. Using only authorized software decreases risk by limiting the number of potential vulnerabilities and by preventing the execution of malware. Cloud approval documentation should include allowed approved ports and protocols communications to include allowlisted mission application traffic and services access from Internet via the DISN Internet Access Point (IAP).

If all or a portion of the mission owners cloud-based level 4/5 systems/applications connected through the BCAP are to be internet accessible, traffic is required to traverse the DISN IAPs. The system’s/application’s URLs/IP addresses must be registered with the DOD DMZ allowlist. Traffic that will typically traverse the IAP is management traffic for level 2 off-premises systems/applications and for user plane traffic to/from level 4/5 systems/applications that are internet-facing. Such traffic and IP addresses may be blocked if not registered in the allowlist.'
  desc 'check', 'Request the cloud service Provisional Approval (PA) and registration documentation. Verify the IaaS/PaaS/software is registered in the service/application with the DOD allowlist for both inbound and outbound traffic when traffic will cross the IAPs. 

If system/service/application is not registered with the DOD allowlist for both inbound and outbound internet facing traffic, this is a finding.'
  desc 'fix', 'This applies to all Impact Levels.
FedRAMP Moderate, High.

Coordinate with CSSP during cloud architecture development to ensure required security relevant data will be accessible via CSP/CSO, third-party security service subscription, and/or native API capability.

Register the IaaS/PaaS/SaaS service/application with the DOD allowlist for both inbound and outbound traffic. Configure the DOD allowlist with the ports and protocols needed to support applications and services used in the cloud environment.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000370-CLD-000120_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000370-CLD-000120'
  tag rid: 'SRG-NET-000370-CLD-000120_rule'
  tag stig_id: 'SRG-NET-000370-CLD-000120'
  tag gtitle: 'SRG-NET-000370-CLD-000120'
  tag fix_id: 'F-SRG-NET-000370-CLD-000120_fix'
  tag 'documentable'
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end

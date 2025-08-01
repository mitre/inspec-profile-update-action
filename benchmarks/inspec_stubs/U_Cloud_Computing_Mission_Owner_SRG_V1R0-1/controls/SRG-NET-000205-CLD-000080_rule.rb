control 'SRG-NET-000205-CLD-000080_rule' do
  title 'The IaaS/PaaS must be configured to maintain separation of all management and data traffic.'
  desc 'The Virtual Datacenter Management system provides a management plane for privileged access and communications. Separation of management and user traffic, including access to the Customer Portal, is provided to the DOD Mission Owner by the CSP for the purpose of provisioning and configuring cloud service offerings. Additionally, service end-points for Application Program Interfaces (API) and Command Line Interfaces (CLI) are also available as part of the Customer Portal network. These systems can be accessed through the internet by DOD privileged users only (e.g., DOD system and network administrators).'
  desc 'check', 'Applies to all impact levels.

Verify the IaaS/PaaS is configured to maintain logical separation of all management and data traffic.

If the IaaS/PaaS does not maintain separation of all management and data traffic, this is a finding.'
  desc 'fix', 'This applies to all Impact Levels.
FedRAMP Moderate, High.

Configure the IaaS/PaaS to maintain separation of all management and data traffic.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000205-CLD-000080_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000205-CLD-000080'
  tag rid: 'SRG-NET-000205-CLD-000080_rule'
  tag stig_id: 'SRG-NET-000205-CLD-000080'
  tag gtitle: 'SRG-NET-000205-CLD-000080'
  tag fix_id: 'F-SRG-NET-000205-CLD-000080_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end

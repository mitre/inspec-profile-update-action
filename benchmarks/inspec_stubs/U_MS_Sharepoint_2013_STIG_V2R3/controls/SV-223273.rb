control 'SV-223273' do
  title 'When configuring SharePoint Central Administration, the port number selected must comply with DoD Ports and Protocol Management (PPSM) program requirements.'
  desc 'During the installation of Microsoft SharePoint, the Central Administration Web site is established on a randomly-assigned TCP port by default. Allowing a randomly-assigned default may result in use of a port which violates DoD policy or conflicts with ports already in use.  Use of certain well-known ports may also result in slow operational response or expose the application to known denial of service attacks.'
  desc 'check', 'Review the SharePoint server Central Administration configuration to ensure the port number selected complies with DoD Ports and Protocol Management (PPSM) program requirements.

Open the SharePoint Management Shell (Start >> All Programs >> Microsoft SharePoint Products >> SharePoint Management Shell). 

Type the following command at the PowerShell prompt:
Get-SPWebApplication -IncludeCentralAdministration

Find the entry for the Central Administration web application and verify the port listed in the URL column is allowed by the DoD PPSM policy.

If the port number is not allowed in accordance with DoD PPSM policy, this is a finding.'
  desc 'fix', 'Configure the SharePoint Central Administration port number selected to comply with DoD Ports and Protocol Management (PPSM) program requirements.

Open the SharePoint Management Shell (Start >> All Programs >> Microsoft SharePoint Products >> SharePoint Management Shell). 

Change the port number to a PPS-approved port that does not conflict with existing port usage using the following command: 
Set -SPCentralAdministration -Port <PortNumber>

Press "Enter" to save.'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24946r430876_chk'
  tag severity: 'medium'
  tag gid: 'V-223273'
  tag rid: 'SV-223273r612235_rule'
  tag stig_id: 'SP13-00-000190'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-24934r430877_fix'
  tag 'documentable'
  tag legacy: ['SV-74439', 'V-60009']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

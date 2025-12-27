control 'SV-234797' do
  title 'Exchange must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the application to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements.'
  desc 'check', "Open a Windows PowerShell Module and enter the following commands: 

Get-Website | Select Name

Get-WebBinding -Name <'WebSiteName'> | Format-List

If the Web binding values returned are not on standard port 80 and 81 for HTTP connections or port 443 and 444 for HTTPS connections, this is a finding.

Repeat the process for each website."
  desc 'fix', 'Configure web ports to be 80, 81 and 443, 444, as specified by PPSM standards.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-37983r617330_chk'
  tag severity: 'medium'
  tag gid: 'V-234797'
  tag rid: 'SV-234797r617332_rule'
  tag stig_id: 'EX13-CA-000165'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-37946r617331_fix'
  tag 'documentable'
  tag legacy: ['SV-84403', 'V-69781']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

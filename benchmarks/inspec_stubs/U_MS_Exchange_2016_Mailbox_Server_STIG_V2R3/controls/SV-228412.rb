control 'SV-228412' do
  title 'The application must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Configuring the application to implement organization-wide security implementation guides and security checklists ensures compliance with Federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements. 

Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the application, including the parameters required to satisfy other security control requirements.'
  desc 'check', "Open a Windows PowerShell Module and enter the following commands: 

Get-Website | Select Name

Get-WebBinding -Name <'WebSiteName'> | Format-List

If the Web binding values returned are not on standard port 80 for HTTP connections or port 443 for HTTPS connections, this is a finding. 

Note: This is excluding the Exchange Back End website which uses 81/444.

Repeat the process for each website."
  desc 'fix', 'Configure web ports to be ports 80 and 443, as specified by PPSM standards.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30645r497032_chk'
  tag severity: 'medium'
  tag gid: 'V-228412'
  tag rid: 'SV-228412r612748_rule'
  tag stig_id: 'EX16-MB-002870'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30630r497033_fix'
  tag 'documentable'
  tag legacy: ['SV-95449', 'V-80739']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

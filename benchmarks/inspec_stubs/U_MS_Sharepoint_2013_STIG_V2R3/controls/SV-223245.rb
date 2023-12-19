control 'SV-223245' do
  title 'SharePoint must provide the ability to prohibit the transfer of unsanctioned information in accordance with security policy.'
  desc 'The application enforces approved authorizations for controlling the flow of information within the system and between interconnected systems in accordance with applicable policy.

Information flow control regulates where information is allowed to travel within an information system and between information systems (as opposed to who is allowed to access the information) and without explicit regard to subsequent accesses to that information.

Specific examples of flow control enforcement can be found in boundary protection devices (e.g., proxies, gateways, guards, encrypted tunnels, firewalls, and routers) employing rule sets or establishing configuration settings restricting information system services, providing a packet-filtering capability based on header information or message-filtering capability based on content (e.g., using key word searches or document characteristics).

Actions to support this requirement include, but are not limited to checking all transferred information for malware, implementing dirty word list searches on transferred information, and applying the same protection measures to metadata (e.g., security attributes) that is applied to the information payload.'
  desc 'check', 'Note: If no unsanctioned information is transferred, and has been documented by the Data Owner, IRM is not required. This requirement is Not Applicable.

Review the SharePoint server configuration to ensure the transfer of unsanctioned information in accordance with security policy is prohibited.

An IRM must be enabled in SharePoint. The Windows Rights Management Services (RMS) (or a comparable IRM product) can either be located through Active Directory or specified.

In Central Administration, click Security.

On the Security page, in the Information policy list, click "Configure information rights management".

If "Do not use IRM on this server" is selected or if a configuration error message is displayed (such as "... IRM will not work until the client is configured properly"), this is a finding.'
  desc 'fix', 'Configure the SharePoint server to prohibit the transfer of unsanctioned information in accordance with security policy.

In Central Administration, click Security.

On the Security page, in the Information policy list, click "Configure information rights management".

Select "Use the default RMS server specified in Active Directory", or identify a specific server by selecting "Use this RMS server:" and entering the server name.

Configure information management policies in accordance with the system security plan requirements.'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24918r430795_chk'
  tag severity: 'medium'
  tag gid: 'V-223245'
  tag rid: 'SV-223245r612235_rule'
  tag stig_id: 'SP13-00-000040'
  tag gtitle: 'SRG-APP-000047'
  tag fix_id: 'F-24906r430796_fix'
  tag 'documentable'
  tag legacy: ['SV-74377', 'V-59947']
  tag cci: ['CCI-001374']
  tag nist: ['AC-4 (15)']
end

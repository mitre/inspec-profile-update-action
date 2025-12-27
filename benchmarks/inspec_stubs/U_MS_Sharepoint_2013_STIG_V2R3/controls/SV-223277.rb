control 'SV-223277' do
  title 'SharePoint must validate the integrity of security attributes exchanged between systems.'
  desc 'When data is exchanged between information systems, the security attributes associated with said data need to be maintained.

Security attributes are an abstraction representing the basic properties or characteristics of an entity with respect to safeguarding information, typically associated with internal data structures (e.g., records, buffers, files) within the information system and used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy.

Security attributes may be explicitly or implicitly associated with the information contained within the information system.'
  desc 'check', 'Note: If no data is exchanged between systems, and has been documented by the Data Owner, IRM is not required. This requirement is Not Applicable.

Review the SharePoint server configuration to ensure the integrity of security attributes exchanged between systems is validated. 

An IRM must be enabled in SharePoint. The Windows Rights Management Services (RMS) (or a comparable IRM product) can either be located through Active Directory or specified.

In Central Administration, click Security.

On the Security page, in the Information policy list, click "Configure information rights management".

If "Do not use IRM on this server" is selected, or if a configuration error message is displayed (such as "... IRM will not work until the client is configured properly"), this is a finding.'
  desc 'fix', 'Configure the SharePoint server to validate the integrity of security attributes exchanged between systems.

In Central Administration, click Security.

On the Security page, in the Information policy list, click "Configure information rights management".

Select "Use the default RMS server specified in Active Directory", or identify a specific server by selecting "Use this RMS server:" and entering the server name.

Configure information management policies in accordance with the system security plan requirements.'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24950r430888_chk'
  tag severity: 'medium'
  tag gid: 'V-223277'
  tag rid: 'SV-223277r612235_rule'
  tag stig_id: 'SP13-00-000105'
  tag gtitle: 'SRG-APP-000204'
  tag fix_id: 'F-24938r430889_fix'
  tag 'documentable'
  tag legacy: ['SV-74403', 'V-59973']
  tag cci: ['CCI-001158']
  tag nist: ['SC-16 (1)']
end

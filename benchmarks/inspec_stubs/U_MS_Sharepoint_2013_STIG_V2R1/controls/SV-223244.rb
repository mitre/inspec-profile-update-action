control 'SV-223244' do
  title 'SharePoint must identify data type, specification, and usage when transferring information between different security domains so policy restrictions may be applied.'
  desc 'Information flow control regulates where information is allowed to travel within an information system and between information systems (as opposed to who is allowed to access the information) and without explicit regard to subsequent accesses to that information.

An example of flow control restrictions includes the following: keeping export-controlled information from being transmitted in the clear to the Internet. Information flow control policies and enforcement mechanisms are commonly employed by organizations to control the flow of information between designated sources and destinations (e.g., users, networks, devices) within information systems and between interconnected systems.

Application-specific examples of flow control enforcement can be found in information protection software (e.g., guards, proxies, application layer gateways, and cross domain solutions) employing rule sets or establishing configuration settings restricting information system services or providing message-filtering capability based on content (e.g., using key word searches or document characteristics).

Flow control is based on the characteristics of the information and/or the information path. Applications providing flow control must identify data type, specification, and usage when transferring information between different security domains so policy restrictions may be applied.

A security domain is defined as a domain implementing a security policy and administered by a single authority.

Data type, specification, and usage includes using file naming to reflect the type of data being transferred and limiting data transfer based on file type.'
  desc 'check', 'Note: If no data is exchanged between different security domains, and has been documented by the Data Owner, IRM is not required. This requirement is Not Applicable.

Review the SharePoint server configuration to ensure data type, specification, and usage when transferring information between different security domains are identified so policy restrictions may be applied.

An IRM must be enabled in SharePoint. The Windows Rights Management Services (RMS) (or a comparable IRM product) can either be located through Active Directory or specified.

In Central Administration, click Security.

On the Security page, in the Information policy list, click "Configure information rights management".

If "Do not use IRM on this server" is selected, or if a configuration error message is displayed (such as "... IRM will not work until the client is configured properly"), this is a finding.'
  desc 'fix', 'Configure the SharePoint server to identify data type, specification, and usage when transferring information between different security domains so policy restrictions may be applied.

In Central Administration, click Security.

On the Security page, in the Information policy list, click "Configure information rights management".

Select "Use the default RMS server specified in Active Directory" or identify a specific server by selecting "Use this RMS server:" and entering the server name.

Configure information management policies in accordance with the system security plan requirements.'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint Server 2013'
  tag check_id: 'C-24917r430792_chk'
  tag severity: 'medium'
  tag gid: 'V-223244'
  tag rid: 'SV-223244r612235_rule'
  tag stig_id: 'SP13-00-000035'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24905r430793_fix'
  tag 'documentable'
  tag legacy: ['V-59945', 'SV-74375']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

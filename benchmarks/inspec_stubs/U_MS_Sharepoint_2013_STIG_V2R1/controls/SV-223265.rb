control 'SV-223265' do
  title 'The SharePoint Central Administration site must not be accessible from Extranet or Internet connections.'
  desc 'SharePoint must prevent the presentation of information system management-related functionality at an interface utilized by general, (i.e., non-privileged), users. 

The Central Administrator is an application used to manage SharePoint system settings and the settings of the web applications running under SharePoint. The Central Administrator application should both be protected using a defense-in-depth approach. Regular users should not be able to access the Central Administrator as the first line of defense. The second line of defense is regular users do not have user ids defined in the Central Administration application.'
  desc 'check', "Review the SharePoint server configuration to ensure Central Administration site is not accessible from Extranet or Internet connections.

Check outside access to Central Administration.

On an administrative work station, open Central Administration and make note of the URL (i.e., http://sharepointserver:7040).

Try to open the Central Administration application on a regular user's workstation. Open a Web browser and type in the URL to Central Administration.

If the Central Administration can be opened, this is a finding."
  desc 'fix', 'Configure the SharePoint Central Administration site to not be accessible from Extranet or Internet connections.

Block outside Central Administrator access.

Use an IIS IP address restrictions, firewall, or other filtering solutions to limit access to Central Administration site.'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint Server 2013'
  tag check_id: 'C-24938r430852_chk'
  tag severity: 'medium'
  tag gid: 'V-223265'
  tag rid: 'SV-223265r612235_rule'
  tag stig_id: 'SP13-00-000150'
  tag gtitle: 'SRG-APP-000212'
  tag fix_id: 'F-24926r430853_fix'
  tag 'documentable'
  tag legacy: ['V-59993', 'SV-74423']
  tag cci: ['CCI-001083']
  tag nist: ['SC-2 (1)']
end

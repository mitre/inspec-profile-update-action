control 'SV-223275' do
  title 'SharePoint server access to the Online Web Part Gallery must be configured for limited access.'
  desc "Web Part galleries are groupings of Web Parts. There are four Web Part galleries: Closed Web Parts, Site Name Gallery, Server Gallery, and Online Gallery. The Online Gallery is a collection of Microsoft MSNBC Web Parts located on the Internet. Allowing users to access the Online Web Part Gallery causes a significant performance hit on the server, due to the server attempting to connect to the MSNBC online gallery. This could result in a Denial-of-Service. The Online Gallery could contain Web Parts from unknown third parties, which could increase the risk of a malicious code execution attack. Preventing users from accessing the Online Web Part Gallery decreases the system's attack surface."
  desc 'check', 'Review the SharePoint server configuration to ensure access to the online web part gallery is configured for limited access.

Log on to Central Administration.

Navigate to the Security page.

Click on "Manage web part security".

For each web application in the web application section, perform the following: 
-Select the correct web application in the web application section.
-Verify "Prevents users from accessing the Online Web Part Gallery, and helps to improve security and performance" option in the Online Web Part Gallery section is selected.

If the "Prevents users from accessing the Online Web Part Gallery, and helps to improve security and performance" option in the Online Web Part Gallery section is not checked, this is a finding.'
  desc 'fix', 'Configure the SharePoint server for limited access to the Online Web Part Gallery.

Enable the "Prevents users from accessing the Online Web Part Gallery, and helps to improve security and performance" option for each web application. 

Log on to Central Administration.

Navigate to the Security page.

Click on "Manage web part security".

For each web application in the web application section, perform the following: 
-Select the correct web application in the web application section.
-Select the "Prevents users from accessing the Online Web Part Gallery, and helps to improve security and performance" option in the Online Web Part Gallery section.

Select "OK".'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint Server 2013'
  tag check_id: 'C-24948r430882_chk'
  tag severity: 'medium'
  tag gid: 'V-223275'
  tag rid: 'SV-223275r612235_rule'
  tag stig_id: 'SP13-00-000205'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24936r430883_fix'
  tag 'documentable'
  tag legacy: ['SV-74421', 'V-59991']
  tag cci: ['CCI-001167', 'CCI-000366']
  tag nist: ['SC-18 (2)', 'CM-6 b']
end

control 'SV-214480' do
  title 'The IIS 8.5 private website must employ cryptographic mechanisms (TLS) and require client certificates.'
  desc 'When data is written to digital media, such as hard drives, mobile computers, external/removable hard drives, personal digital assistants, flash/thumb drives, etc., there is risk of data loss and data compromise. User identities and passwords stored on the hard drive of the hosting hardware must be encrypted to protect the data from easily being discovered and used by an unauthorized user to access the hosted applications. The cryptographic libraries and functionality used to store and retrieve the user identifiers and passwords must be part of the web server.

Preventing the disclosure of transmitted information requires that the web server take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS). 

Transmission of data can take place between the web server and a large number of devices/applications external to the web server. Examples are a web client used by a user, a backend database, an audit server, or other web servers in a web cluster. 

If data is transmitted unencrypted, the data then becomes vulnerable to disclosure. The disclosure may reveal user identifier/password combinations, website code revealing business logic, or other user personal information.

Also satisfies: SRG-APP-000439-WSR-000151'
  desc 'check', 'Note: If SSL is installed on load balancer/proxy server through which traffic is routed to the IIS 8.5 server, and the IIS 8.5 server receives traffic from the load balancer/proxy server, the SSL requirement must be met on the load balancer/proxy server.

Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.
Double-click the "SSL Settings" icon under the "IIS" section.
Verify "Require SSL" is checked.
Verify "Client Certificates Required" is selected.
Click the site under review.
Select "Configuration Editor" under the "Management" section.
From the "Section:" drop-down list at the top of the configuration editor, locate “system.webServer/security/access”.
The value for "sslFlags" set must include "ssl128".

If the "Require SSL" is not selected, this is a finding.
If the "Client Certificates Required" is not selected, this is a finding.
If the "sslFlags" is not set to "ssl128", this is a finding.'
  desc 'fix', 'Follow the procedures below for each site hosted on the IIS 8.5 web server:

Open the IIS 8.5 Manager.

Double-click the "SSL Settings" icon under the "IIS" section.

Select the "Require SSL" setting.

Select the "Client Certificates Required" setting.

Click "Apply" in the "Actions" pane.

Click the site under review.

Select "Configuration Editor" under the "Management" section.

From the "Section:" drop-down list at the top of the configuration editor, locate “system.webServer/security/access”.

Click on the drop-down list for "sslFlags".

Select the "Ssl128" check box.

Click "Apply" in the "Actions" pane.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Site'
  tag check_id: 'C-15689r310644_chk'
  tag severity: 'medium'
  tag gid: 'V-214480'
  tag rid: 'SV-214480r508659_rule'
  tag stig_id: 'IISW-SI-000242'
  tag gtitle: 'SRG-APP-000429-WSR-000113'
  tag fix_id: 'F-15687r310645_fix'
  tag 'documentable'
  tag legacy: ['SV-91547', 'V-76851']
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end

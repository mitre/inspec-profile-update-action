control 'SV-223240' do
  title 'SharePoint must utilize approved cryptography to protect the confidentiality of remote access sessions.'
  desc 'Remote access is any access to an organizational information system by a user (or an information system) communicating through an external, non-organization-controlled network (e.g., the Internet). Examples of remote access methods include dial-up, broadband, and wireless.

Remote network access is accomplished by leveraging common communication protocols and establishing a remote connection. These connections will typically occur over either the public Internet or the Public Switched Telephone Network (PSTN). Since neither of these Internetworking mechanisms are private nor secure, if cryptography is not used, then the session data traversing the remote connection could be intercepted and compromised. Cryptography provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection, thereby providing a degree of confidentiality. The encryption strength of mechanism is selected based on the security categorization of the information traversing the remote connection.'
  desc 'check', 'Review the SharePoint server configuration to ensure approved cryptography is being utilized to protect the confidentiality of remote access sessions.

Navigate to Central Administration.

Under “System Settings”, click “Configure Alternate Access mappings”.

Review the “Public URL for zone” column values. If any URL does not begin with “https”, this is a finding.'
  desc 'fix', %q(Configure the SharePoint server to use approved cryptography to protect the confidentiality of remote access sessions.

Open IIS Manager.

In the Connections pane, expand "Sites".

Click the "Web Application" site.

In the Actions pane, click "Bindings".

In the Site Bindings window, click "Add".

In the Add Site Binding window, change "Type" to "https", and select the site's SSL certificate. Click "OK".

Remove all bindings that do not use https.

Click "Close".)
  impact 0.7
  ref 'DPMS Target Microsoft SharePoint Server 2013'
  tag check_id: 'C-24913r430780_chk'
  tag severity: 'high'
  tag gid: 'V-223240'
  tag rid: 'SV-223240r612235_rule'
  tag stig_id: 'SP13-00-000015'
  tag gtitle: 'SRG-APP-000014'
  tag fix_id: 'F-24901r430781_fix'
  tag 'documentable'
  tag legacy: ['V-59937', 'SV-74367']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end

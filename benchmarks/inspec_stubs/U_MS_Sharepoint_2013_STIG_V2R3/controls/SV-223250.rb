control 'SV-223250' do
  title 'SharePoint must use replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security), and time synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Review the SharePoint server configuration to ensure replay-resistant authentication mechanisms for network access to privileged accounts are used.

SharePoint must be configured to use Kerberos as the primary authentication provider.

Log on to the server.

Click Start.

Type Internet Information Services Manager in the Search Bar, click Enter.

Expand the server node in the tree view and expand the "Sites" node.

*For each...* Select a SharePoint Web Application site to review.

In the "IIS" section, double-click Authentication and then select "Windows Authentication".

Right-click "Windows Authentication" and select "Providers".

Ensure "Negotiate" is listed first. If NTLM is listed first in the Enabled Providers box, this is a finding.'
  desc 'fix', 'Configure the SharePoint server to use replay-resistant authentication mechanisms for network access to privileged accounts.

If the web application is using Integrated Windows Authentication as the claims provider, perform the following:

Open the Central Administration site, select "Application Management".

On the "Application Management" page, select "Manage Web Applications", select the web application that corresponds to the site reviewed in the "Check" section above, then click the "Authentication Providers" button in the ribbon.

Select the zone corresponding to the web application being reviewed, which will open the "Edit Authentication" dialog in the "Claims Authentication Types" section, select "Negotiate (Kerberos)" in the "Integrated Windows Authentication" dropdown, then click "Save".'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24923r430810_chk'
  tag severity: 'medium'
  tag gid: 'V-223250'
  tag rid: 'SV-223250r612235_rule'
  tag stig_id: 'SP13-00-000075'
  tag gtitle: 'SRG-APP-000156'
  tag fix_id: 'F-24911r430811_fix'
  tag 'documentable'
  tag legacy: ['SV-74391', 'V-59961']
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end

control 'SV-223259' do
  title 'SharePoint must maintain the confidentiality of information during aggregation, packaging, and transformation in preparation for transmission. When transmitting data, applications need to leverage transmission protection mechanisms such as TLS, SSL VPNs, or IPSec.'
  desc 'Preventing the disclosure of transmitted information requires that applications take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPSec tunnel.

Alternative physical protection measures include protected distribution systems. Protective Distribution Systems (PDS) are used to transmit unencrypted classified NSI through an area of lesser classification or control. Inasmuch as the classified NSI is unencrypted, the PDS must provide adequate electrical, electromagnetic, and physical safeguards to deter exploitation. Refer to NSTSSI No. 7003 for additional details on a PDS.'
  desc 'check', 'Review the SharePoint server configuration to ensure the confidentiality of information during aggregation, packaging, and transformation in preparation for transmission is maintained.

In SharePoint Central Administration, click Application Management.

On the Application Management page, in the Web Applications list, click Manage web applications.

On the Web Applications Management page, verify that each Web Application URL begins with https.

If the URL does not begin with https, this is a finding.

If SharePoint communications between all components and clients are protected by alternative physical measures that have been approved by the AO, this is not a finding.'
  desc 'fix', "Configure the SharePoint server to maintain the confidentiality of information during aggregation, packaging, and transformation in preparation for transmission.

Open IIS Manager.

In the Connections pane, expand Sites.

Click the Web Application site.

In the Actions pane, click Bindings.

In the Site Bindings window, click Add.

In the Add Site Binding window, change Type to https, and select the site's SSL certificate.

Click OK, and then click Close."
  impact 0.7
  ref 'DPMS Target Microsoft SharePoint Server 2013'
  tag check_id: 'C-24932r430834_chk'
  tag severity: 'high'
  tag gid: 'V-223259'
  tag rid: 'SV-223259r612235_rule'
  tag stig_id: 'SP13-00-000120'
  tag gtitle: 'SRG-APP-000441'
  tag fix_id: 'F-24920r430835_fix'
  tag 'documentable'
  tag legacy: ['SV-74409', 'V-59979']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end

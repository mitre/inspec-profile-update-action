control 'SV-223262' do
  title 'SharePoint must employ cryptographic mechanisms preventing the unauthorized disclosure of information during transmission, unless the transmitted data is otherwise protected by alternative physical measures.'
  desc 'Preventing the disclosure of transmitted information requires that applications take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPSEC tunnel.

Alternative physical protection measures include Protected Distribution Systems (PDS). PDS are used to transmit unencrypted classified NSI through an area of lesser classification or control. Inasmuch as the classified NSI is unencrypted, the PDS must provide adequate electrical, electromagnetic, and physical safeguards to deter exploitation. Refer to NSTSSI No. 7003 for additional details on a PDS.'
  desc 'check', 'Review the SharePoint server to ensure cryptographic mechanisms preventing the unauthorized disclosure of information during transmission are employed, unless the transmitted data is otherwise protected by alternative physical measures.

In SharePoint Central Administration, click Application Management.

On the Application Management page, in the Web Applications list, click Manage web applications.

On the Web Applications Management page, verify that each Web Application URL begins with https.

If the URL does not begin with https, this is a finding.

If SharePoint communications between all components and clients are protected by alternative physical measures that have been approved by the AO, this is not a finding.'
  desc 'fix', "Configure the SharePoint server to employ cryptographic mechanisms preventing the unauthorized disclosure of information during transmission, unless the transmitted data is otherwise protected by alternative physical measures.

Open IIS Manager.

In the Connections pane, expand Sites.

Click the Web Application site.

In the Actions pane, click Bindings.

In the Site Bindings window, click Add.

In the Add Site Binding window, change Type to https, and select the site's SSL certificate.

Click OK, and then click Close."
  impact 0.7
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24935r430843_chk'
  tag severity: 'high'
  tag gid: 'V-223262'
  tag rid: 'SV-223262r612235_rule'
  tag stig_id: 'SP13-00-000135'
  tag gtitle: 'SRG-APP-000440'
  tag fix_id: 'F-24923r430844_fix'
  tag 'documentable'
  tag legacy: ['SV-74415', 'V-59985']
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end

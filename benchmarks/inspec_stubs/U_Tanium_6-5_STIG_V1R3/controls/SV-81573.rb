control 'SV-81573' do
  title 'The Tanium Server certificates must have Extended Key Usage entries for the serverAuth object TLS Web Server Authentication and the clientAuth object TLS Web Client Authentication.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When receiving data, applications need to leverage protection mechanisms, such as TLS, SSL VPNs, or IPSEC.'
  desc 'check', 'Access the Tanium Module server interactively and log on as an Administrator.

Navigate to the \\Program Files\\Tanium\\Tanium Server directory.

Locate the SOAPServer.crt file and double-click on it to open the certificate.
Select the “Details” tab.
Scroll down through the details to find and select the “Extended Key Usage” Field.

If there is no “Extended Key Usage” field, this is a finding.

In the bottom screen, verify "TLS Web Server Authentication" and "TLS Web Client Authentication" are both identified.

If "TLS Web Server Authentication" and "TLS Web Client Authentication" are not both identified, this is a finding.'
  desc 'fix', 'Request or regenerate the certificate being used to include both the serverAuth and clientAuth objects.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67719r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67083'
  tag rid: 'SV-81573r1_rule'
  tag stig_id: 'TANS-SV-000020'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-73183r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end

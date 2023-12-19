control 'SV-234092' do
  title 'The Tanium Server certificates must have Extended Key Usage entries for the serverAuth object TLS Web Server Authentication and the clientAuth object TLS Web Client Authentication.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When receiving data, applications need to leverage protection mechanisms, such as TLS, SSL VPNs, or IPsec.'
  desc 'check', 'Access the Tanium Application server interactively.

Log on to the server with an account that has administrative privileges.

Navigate to Program Files >> Tanium >> Tanium Server.

Locate the "SOAPServer.crt" file.

Double-click on the file to open the certificate.

Select the "Details" tab.

Scroll down through the details to find and select the "Enhanced Key Usage" field.

If there is no "Enhanced Key Usage" field, this is a finding.

In the bottom screen, verify "Server Authentication" and "Client Authentication" are both identified.

If "Server Authentication" and "Client Authentication" are not both identified, this is a finding.'
  desc 'fix', 'Request or regenerate the certificate being used to include both the "Server Authentication" and "Client Authentication" objects.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37277r610776_chk'
  tag severity: 'medium'
  tag gid: 'V-234092'
  tag rid: 'SV-234092r612749_rule'
  tag stig_id: 'TANS-SV-000020'
  tag gtitle: 'SRG-APP-000175'
  tag fix_id: 'F-37242r610777_fix'
  tag 'documentable'
  tag legacy: ['SV-102257', 'V-92155']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end

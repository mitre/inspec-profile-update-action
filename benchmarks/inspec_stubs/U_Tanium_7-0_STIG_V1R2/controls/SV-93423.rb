control 'SV-93423' do
  title 'Any Tanium configured EMAIL RESULTS connectors must be configured to enable TLS/SSL to encrypt communications.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, SSL VPNs, or IPsec.

An example of this would be the SMTP queue. The SMTP mail protocol places email messages into a centralized queue prior to transmission. If someone were to modify an email message contained in the queue and the SMTP protocol did not check to ensure the email message was not modified while it was stored in the queue, a modified email could be sent.'
  desc 'check', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

If no "Email" connectors are configured under "Destinations", this is Not Applicable.

For each "Email" connector, select the connector to reveal its properties.

Validate the "Enable TLS" is set to "true".

If any configured "Email" connectors are configured for "Enable TLS" set to "false", this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Click on "Email" on the Destinations column.

Select each "Email" connector that is configured with "Enable TLS" set to "false".

Click the "Edit" button at the top right of the screen.

Place a check in the "Enable TLS" check box.

Click on "Save Changes".'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78287r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78717'
  tag rid: 'SV-93423r1_rule'
  tag stig_id: 'TANS-SV-000037'
  tag gtitle: 'SRG-APP-000442'
  tag fix_id: 'F-85453r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end

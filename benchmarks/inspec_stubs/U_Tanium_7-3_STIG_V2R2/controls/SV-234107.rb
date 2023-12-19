control 'SV-234107' do
  title 'Any Tanium configured EMAIL RESULTS connectors must be configured to enable TLS/SSL to encrypt communications.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, SSL VPNs, or IPsec.

An example of this would be the SMTP queue. The SMTP mail protocol places email messages into a centralized queue prior to transmission. If someone were to modify an email message contained in the queue and the SMTP protocol did not check to ensure the email message was not modified while it was stored in the queue, a modified email could be sent.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Review the configured Destinations listed.

If an "Email" Destination does not exist, this is not a finding.

Select "Email" destination.

Select each Connection found in the lower half of the screen.

Verify "Enable TLS" is "true".

If "Enable TLS" is "false", this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Review the configured Destinations listed.

Select "Email" destination.

Select the Connection found in the lower half of the screen.

Click "Edit" on the top right of the summary page.

Under the "Source and Destination" section, select the "Enable TLS" checkbox under the "Mail Configuration".

Confirm the rest of the data is correct.

Click "Save" at the bottom of the page.

Do this for all Connections configured with an "Email" destination.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37292r610821_chk'
  tag severity: 'medium'
  tag gid: 'V-234107'
  tag rid: 'SV-234107r612749_rule'
  tag stig_id: 'TANS-SV-000037'
  tag gtitle: 'SRG-APP-000442'
  tag fix_id: 'F-37257r610822_fix'
  tag 'documentable'
  tag legacy: ['SV-102287', 'V-92185']
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end

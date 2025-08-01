control 'SV-234077' do
  title 'The Tanium Server must protect the confidentiality and integrity of transmitted information, in preparation to be transmitted and data at rest, with cryptographic signing capabilities enabled to protect the authenticity of communications sessions when making requests from Tanium Clients.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered.

This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, SSL VPNs, or IPsec.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.

'
  desc 'check', 'Using a web browser on a system, which has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Global Settings" tab.

In the "Show Settings Containing:" search box type "ReportingTLSMode". Enter.

If no results are returned, this is a finding.

In the "Show Settings Containing:" search box type "StateProtectedFlag". Enter.

If no results are returned or "StateProtectedFlag = 0", this is a finding.

If results are returned for "ReportingTLSMode" but the value is "0", this is a finding.'
  desc 'fix', 'Using a web browser on a system, which has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Global Settings" tab.

Click on "New Setting".

In "New System Setting" dialog window to the right, enter "ReportingTLSMode" for "Setting Name:".

Enter "2" for "Setting Value:".

Select "Client" from "Affects" drop-down list.

Select "Numeric" from "Value Type" drop-down list.

Click "Save".   
Click on "New Setting".

In "New System Setting" dialog window to the right, enter "StateProtectedFlag" for "Setting Name:".

Enter "1" for "Setting Value:".

Select "Client" from "Affects" drop-down list.

Select "Numeric" from "Value Type" drop-down list.

Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37262r610731_chk'
  tag severity: 'medium'
  tag gid: 'V-234077'
  tag rid: 'SV-234077r612749_rule'
  tag stig_id: 'TANS-SV-000001'
  tag gtitle: 'SRG-APP-000429'
  tag fix_id: 'F-37227r612218_fix'
  tag satisfies: ['SRG-APP-000429', 'SRG-APP-000440', 'SRG-APP-000441']
  tag 'documentable'
  tag legacy: ['V-92125', 'SV-102227']
  tag cci: ['CCI-002476', 'CCI-002420', 'CCI-002421']
  tag nist: ['SC-28 (1)', 'SC-8 (2)', 'SC-8 (1)']
end

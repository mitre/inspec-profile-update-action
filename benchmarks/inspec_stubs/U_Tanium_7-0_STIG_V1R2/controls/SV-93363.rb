control 'SV-93363' do
  title 'The Tanium Server must protect the confidentiality and integrity of transmitted information with cryptographic signing capabilities enabled to ensure the authenticity of communications sessions when making requests from Tanium Clients.'
  desc "Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered. Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

This requirement applies only to applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, SSL VPNs, or IPsec.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, logical means (cryptography) do not have to be employed, and vice versa.

All of Tanium's signing capabilities should be enabled upon install. Tanium supports the cryptographic signing and verification before execution of all Sensors, Questions, Actions, Sensor Libraries, File Shards, etc. Enabling signing does away with the ability of an attacker to conduct man-in-the-middle (MitM) attacks for the purposes of remote code execution and precludes the modification of the aforementioned data elements in transit. Additionally, Tanium supports object-level signing for content ingested into the Tanium platform. This allows for the detection and rejection of changes to objects (sensors, actions, etc.) by even a privileged user within Tanium.

Tanium has built-in signing capabilities enabled by default when installed. Cryptographic signing and verification of all Sensors, Questions, Actions, Sensor Libraries, File Shards, etc. before execution will be enforced by Tanium.

Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

Application communication sessions are protected using transport encryption protocols, such as SSL or TLS. SSL/TLS provides web applications with a way to authenticate user sessions and encrypt application traffic. Session authentication can be single (one-way) or mutual (two-way) in nature. Single authentication authenticates the server for the client, whereas mutual authentication provides a means for both the client and the server to authenticate each other.

This requirement applies to applications that use communications sessions. This includes but is not limited to web-based applications and Service-Oriented Architectures (SOA).

This requirement addresses communications protection at the application session, versus the network packet, and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of SSL/TLS mutual authentication (two-way/bidirectional).

"
  desc 'check', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Global Settings" tab.

In the "Show Settings Containing:" search box type "sign_all_questions_flag". 

Click "Enter".

If no results are returned, this is a finding.

If results are returned for "sign_all_questions_flag" but the value is not "1", this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Global Settings" tab.

Click on "New Setting".

In "New System Setting" dialog box, enter "sign_all_questions_flag" for "Setting Name:".

Enter "1" for "Setting Value:".

Select "Server" from "Affects" drop-down list.

Select "Numeric" from "Value Type" drop-down list.

Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78227r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78657'
  tag rid: 'SV-93363r1_rule'
  tag stig_id: 'TANS-SV-000001'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-85393r1_fix'
  tag satisfies: ['SRG-APP-000439', 'SRG-APP-000395', 'SRG-APP-000441', 'SRG-APP-000131', 'SRG-APP-000219']
  tag 'documentable'
  tag cci: ['CCI-001184', 'CCI-001749', 'CCI-001967', 'CCI-002418', 'CCI-002420']
  tag nist: ['SC-23', 'CM-5 (3)', 'IA-3 (1)', 'SC-8', 'SC-8 (2)']
end

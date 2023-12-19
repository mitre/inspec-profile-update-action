control 'SV-81481' do
  title 'The Tanium Client must ensure the authenticity of communications sessions when answering requests from the Tanium Server.'
  desc 'Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

Application communication sessions are protected utilizing transport encryption protocols, such as SSL or TLS. SSL/TLS provides web applications with a means to be able to authenticate user sessions and encrypt application traffic. Session authentication can be single (one-way) or mutual (two-way) in nature. Single authentication authenticates the server for the client, whereas mutual authentication provides a means for both the client and the server to authenticate each other.

This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA). 

This requirement addresses communications protection at the application session, versus the network packet, and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of SSL/TLS mutual authentication (two-way/bidirectional).'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on "Administration".

Select the "Global Settings" tab.

In the search box beside "Show Settings Containing:" type "AllQuestionsRequireSignatureFlag". Enter.

If no results are returned, this is a finding since this setting needs to be explicitly set.

If results are returned for "AllQuestionsRequireSignatureFlag" but the value is not "1", this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on "Administration".

Select the "Global Settings" tab.

Click on "+ Add New Setting".

In "Create New Setting" dialog box, enter "AllQuestionsRequireSignatureFlag" for "Setting Name:".

Enter "1" for "Setting Value:".

Select "Numeric" from "Value Type" drop-down list. 

Select "Clients" from "Affects" drop-down list.

Click “Save”.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67627r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66991'
  tag rid: 'SV-81481r1_rule'
  tag stig_id: 'TANS-CL-000011'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-73091r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end

control 'SV-214264' do
  title 'The Apache web server must be configured to integrate with an organizations security infrastructure.'
  desc 'A web server will typically use logging mechanisms for maintaining a historical log of activity that occurs within a hosted application. This information can then be used for diagnostic purposes, forensics purposes, or other purposes relevant to ensuring the availability and integrity of the hosted application.

While it is important to log events identified as being critical and relevant to security, it is equally important to notify the appropriate personnel in a timely manner so they are able to respond to events as they occur. 

Manual review of the web server logs may not occur in a timely manner, and each event logged is open to interpretation by a reviewer. By integrating the web server into an overall or organization-wide log review, a larger picture of events can be viewed, and analysis can be done in a timely and reliable manner.'
  desc 'check', 'Work with the SIEM administrator to determine current security integrations. 

If the SIEM is not integrated with security, this is a finding.'
  desc 'fix', 'Work with the SIEM administrator to integrate with an organizations security infrastructure.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15478r277052_chk'
  tag severity: 'medium'
  tag gid: 'V-214264'
  tag rid: 'SV-214264r612240_rule'
  tag stig_id: 'AS24-U1-000730'
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag fix_id: 'F-15476r277053_fix'
  tag 'documentable'
  tag legacy: ['V-92719', 'SV-102807']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end

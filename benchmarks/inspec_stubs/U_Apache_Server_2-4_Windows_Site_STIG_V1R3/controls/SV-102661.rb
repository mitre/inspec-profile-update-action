control 'SV-102661' do
  title 'The Apache web server must prohibit or restrict the use of nonsecure or unnecessary ports, protocols, modules, and/or services.'
  desc 'Web servers provide numerous processes, features, and functionalities that use TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system.

The web server must provide the capability to disable or deactivate network-related services that are deemed to be non-essential to the server mission, are too unsecure, or are prohibited by the Ports, Protocols, and Services Management (PPSM) Category Assurance List (CAL) and vulnerability assessments.'
  desc 'check', "Review the web server documentation and deployment configuration to determine which ports and protocols are enabled.
 
Verify
 the ports and protocols being used are permitted, necessary for the 
operation of the web server and the hosted applications, and are secure 
for a production system.
 
Open the <'INSTALLED PATH'>\\conf\\httpd.conf file.
 
Verify only the listener for IANA well-known ports for HTTP and HTTPS are in use.
 
If
 any of the ports or protocols are not permitted, are nonsecure, or are 
not necessary for web server operation, this is a finding."
  desc 'fix', 'Ensure the website enforces the use of IANA well-known ports for HTTP and HTTPS.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.4 - Windows'
  tag check_id: 'C-91877r2_chk'
  tag severity: 'medium'
  tag gid: 'V-92573'
  tag rid: 'SV-102661r1_rule'
  tag stig_id: 'AS24-W2-000780'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag fix_id: 'F-98815r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end

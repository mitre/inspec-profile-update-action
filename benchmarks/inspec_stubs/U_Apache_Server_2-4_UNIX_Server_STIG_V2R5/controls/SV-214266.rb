control 'SV-214266' do
  title 'The Apache web server must prohibit or restrict the use of nonsecure or unnecessary ports, protocols, modules, and/or services.'
  desc 'Web servers provide numerous processes, features, and functionalities that use TCP/IP ports. Some of these processes may be deemed unnecessary or too unsecure to run on a production system.

The Apache web server must provide the capability to disable or deactivate network-related services that are deemed to be non-essential to the server mission, are too unsecure, or are prohibited by the Ports, Protocols, and Services Management (PPSM) Category Assurance List (CAL) and vulnerability assessments.'
  desc 'check', 'Review the website to determine if HTTP and HTTPs are used in accordance with well known ports (e.g., 80 and 443) or those ports and services as registered and approved for use by the DoD PPSM. Any variation in PPS will be documented, registered, and approved by the PPSM. If not, this is a finding.'
  desc 'fix', 'Ensure the website enforces the use of IANA well-known ports for HTTP and HTTPS.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15480r277058_chk'
  tag severity: 'medium'
  tag gid: 'V-214266'
  tag rid: 'SV-214266r879756_rule'
  tag stig_id: 'AS24-U1-000780'
  tag gtitle: 'SRG-APP-000383-WSR-000175'
  tag fix_id: 'F-15478r277059_fix'
  tag 'documentable'
  tag legacy: ['V-92727', 'SV-102815']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end

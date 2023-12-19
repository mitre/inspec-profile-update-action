control 'SV-33070' do
  title 'A web server installation must be segregated from other services.'
  desc 'The web server installation and configuration plan should not support the co-hosting of multiple services such as Domain Name Service (DNS), e-mail, databases, search engines, indexing, or streaming media on the same server that is providing the web publishing service.  By separating these services additional defensive layers are established between the web service and the applicable application should either be compromised.   

Disallowed or restricted services in the context of this vulnerability applies to services that are not directly associated with the delivery of web content. An operating system that supports a web server will not provide other services (e.g., domain controller, e-mail server, database server, etc.). Only those services necessary to support the web server and its hosted sites are specifically allowed and may include, but are not limited to, operating system, logging, anti-virus, host intrusion detection, administrative maintenance, or network requirements.'
  desc 'check', 'Request a copy of and review the web server’s installation and configuration plan. Ensure that the server is in compliance with this plan. If the server is not in compliance with the plan, this is a finding.

Query the SA to ascertain if and where the additional services are installed.

Confirm that the additional service or application is not installed on the same partition as the operating systems root, web server root, or web document root. If it is, this is a finding.'
  desc 'fix', 'Move or install additional services and applications to partitions that are not the operating system root, web server root, or web document root.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33742r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6577'
  tag rid: 'SV-33070r1_rule'
  tag stig_id: 'WG204 W22'
  tag gtitle: 'WG204'
  tag fix_id: 'F-29377r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end

control 'SV-221456' do
  title 'OHS must be segregated from other services.'
  desc 'The web server installation and configuration plan should not support the co-hosting of multiple services such as Domain Name Service (DNS), e-mail, databases, search engines, indexing, or streaming media on the same server that is providing the web publishing service.  By separating these services, physically or logically, additional defensive layers are established between the web service and the applicable application should either be compromised.   

Disallowed or restricted services in the context of this vulnerability applies to services that are not directly associated with the delivery of web content. An operating system that supports a web server will not provide other services (e.g., domain controller, e-mail server, database server, etc.). Only those services necessary to support the web server and its hosted sites are specifically allowed and may include, but are not limited to, operating system, logging, anti-virus, host intrusion detection, administrative maintenance, or network requirements.'
  desc 'check', '1. Obtain a copy of the OHS installation and configuration plan.

2. Ask the System Administrator whether any additional services (e.g., database, DNS, mail, application server, etc.) are installed with OHS that do not directly support operation or management of OHS. Separation of services may be physical or logical.

3. If so, this is a finding.'
  desc 'fix', 'Move any software from the OHS installation that is not required for the operation or management of the OHS server to another physical or logical server.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23171r415051_chk'
  tag severity: 'medium'
  tag gid: 'V-221456'
  tag rid: 'SV-221456r879887_rule'
  tag stig_id: 'OH12-1X-000219'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23160r415052_fix'
  tag 'documentable'
  tag legacy: ['SV-79165', 'V-64675']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

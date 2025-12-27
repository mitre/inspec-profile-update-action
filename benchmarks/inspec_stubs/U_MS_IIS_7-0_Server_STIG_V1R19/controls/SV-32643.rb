control 'SV-32643' do
  title 'A web server must not be co-hosted with other services.'
  desc 'A detailed web server installation and configuration plan should be followed to provide standardization during the installation process.  The installation and configuration plan should not support the co-hosting of multiple services, such as, Domain Name Service (DNS), e-mail, databases, search engines, indexing, or streaming media on the same server that is providing the web publishing service.

Disallowed or restricted services in the context of this vulnerability applies to services that are not directly associated with the delivery of web content. An operating system supporting a web server will not provide other services (e.g., domain controller, email server, database server, etc.). Only those services necessary to support the web server and its hosted sites are specifically allowed and may include, but are not limited to, operating system, logging, anti-virus, host intrusion detection, administrative maintenance, or network requirements. Any unnecessary services or protocols should be removed.'
  desc 'check', "Request a copy of and review the web server's installation and configuration plan for required services.
 
Ensure the server only has the required services installed as documented in the installation and configuration plan.
 
If the server has any additional services, this is a finding."
  desc 'fix', 'Remove any services or applications that are not required.'
  impact 0.5
  ref 'DPMS Target IIS Installation 7'
  tag check_id: 'C-29993r2_chk'
  tag severity: 'medium'
  tag gid: 'V-6577'
  tag rid: 'SV-32643r3_rule'
  tag stig_id: 'WG204 IIS7'
  tag gtitle: 'WG204'
  tag fix_id: 'F-26852r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end

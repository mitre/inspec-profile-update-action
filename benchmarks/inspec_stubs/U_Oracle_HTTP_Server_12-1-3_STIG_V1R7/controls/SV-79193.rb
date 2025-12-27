control 'SV-79193' do
  title 'OHS hosted web sites must utilize ports, protocols, and services according to PPSM guidelines.'
  desc 'Failure to comply with DoD ports, protocols, and services (PPS) requirements can result in compromise of enclave boundary protections and/or functionality of the automated information system (AIS).

The ISSM will ensure web servers are configured to use only authorized PPS in accordance with the Network Infrastructure STIG, DoD Instruction 8551.1, Ports, Protocols, and Services Management (PPSM), and the associated Ports, Protocols, and Services (PPS) Assurance Category Assignments List.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "Listen" directive at the OHS server configuration scope.

3. If the "Listen" directive port specified is not "80" or "443", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "Listen" directive at the OHS server configuration scope.

3. Set the "Listen" directive to "80" for http ports and "443" for https ports.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65445r1_chk'
  tag severity: 'low'
  tag gid: 'V-64703'
  tag rid: 'SV-79193r1_rule'
  tag stig_id: 'OH12-1X-000233'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70633r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

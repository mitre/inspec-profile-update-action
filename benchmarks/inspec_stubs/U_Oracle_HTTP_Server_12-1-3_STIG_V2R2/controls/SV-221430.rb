control 'SV-221430' do
  title 'OHS must limit access to the Dynamic Monitoring Service (DMS).'
  desc 'The Oracle Dynamic Monitoring Service (DMS) enables application developers, support analysts, system administrators, and others to measure application specific performance information.  If OHS allows any machine to connect and monitor performance, an attacker could connect and gather information that could be used to cause a DoS for OHS.  Information that is shared could also be used to further an attack to other servers and devices through trusted relationships.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/admin.conf in it with an editor.

2. Search for the "Allow" directive within the "<Location /dms/>" directive at the virtual host configuration scope.

3. If the "Allow" directive is set to "from all", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/admin.conf with an editor.

2. Search for the "Allow" directive within the "<Location /dms/>" virtual host configuration scope.

3. Set the "Allow" directive to "from 127.0.0.1".'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23145r414973_chk'
  tag severity: 'medium'
  tag gid: 'V-221430'
  tag rid: 'SV-221430r879887_rule'
  tag stig_id: 'OH12-1X-000192'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23134r414974_fix'
  tag 'documentable'
  tag legacy: ['SV-79113', 'V-64623']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

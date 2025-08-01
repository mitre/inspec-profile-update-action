control 'SV-214346' do
  title 'An Apache web server that is part of a web server cluster must route all remote management through a centrally managed access control point.'
  desc 'A web server cluster is a group of independent Apache web servers that are managed as a single system for higher availability, easier manageability, and greater scalability. Without having centralized control of the web server cluster, management of the cluster becomes difficult. It is critical that remote management of the cluster be done through a designated management system acting as a single access point.'
  desc 'check', %q(Review the <'INSTALL PATH'>\conf\httpd.conf file.

Verify the "mod_proxy" is loaded.

If it does not exist, this is a finding.

If the "mod_proxy" module is loaded and the "ProxyPass" directive is not configured, this is a finding.)
  desc 'fix', %q(Edit the <'INSTALL PATH'>\conf\httpd.conf file and load the "mod_proxy" module.

Set the "ProxyPass" directive.

Restart the Apache service.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15558r277541_chk'
  tag severity: 'medium'
  tag gid: 'V-214346'
  tag rid: 'SV-214346r505936_rule'
  tag stig_id: 'AS24-W1-000700'
  tag gtitle: 'SRG-APP-000356-WSR-000007'
  tag fix_id: 'F-15556r277542_fix'
  tag 'documentable'
  tag legacy: ['SV-102533', 'V-92445']
  tag cci: ['CCI-001844']
  tag nist: ['AU-3 (2)']
end

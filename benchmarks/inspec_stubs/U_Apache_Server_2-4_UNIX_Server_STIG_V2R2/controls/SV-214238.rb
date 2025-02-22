control 'SV-214238' do
  title 'Expansion modules must be fully reviewed, tested, and signed before they can exist on a production Apache web server.'
  desc 'In the case of a production web server, areas for content development and testing will not exist, as this type of content is only permissible on a development website. The process of developing on a functional production website entails a degree of trial and error and repeated testing. This process is often accomplished in an environment where debugging, sequencing, and formatting of content are the main goals. The opportunity for a malicious user to obtain files that reveal business logic and logon schemes is high in this situation. The existence of such immature content on a web server represents a significant security risk that is totally avoidable.

The web server must enforce, internally or through an external utility, the signing of modules before they are implemented into a production environment. By signing modules, the author guarantees that the module has been reviewed and tested before production implementation.'
  desc 'check', 'Enter the following command:

"httpd -M"

This will provide a list of the loaded modules. Validate that all displayed modules are required for operations.

If any module is not required for operation, this is a finding.

NOTE: The following modules are needed for basic web function and do not need to be reviewed:

core_module
http_module
so_module
mpm_prefork_module

For a complete list of signed Apache Modules, review https://httpd.apache.org/docs/2.4/mod/.'
  desc 'fix', 'Remove any unsigned modules.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15452r276974_chk'
  tag severity: 'medium'
  tag gid: 'V-214238'
  tag rid: 'SV-214238r612240_rule'
  tag stig_id: 'AS24-U1-000230'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag fix_id: 'F-15450r276975_fix'
  tag 'documentable'
  tag legacy: ['SV-102725', 'V-92637']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end

control 'SV-221533' do
  title 'OHS must have the SSLFIPS directive enabled to maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

An example of this would be an SMTP queue. This queue may be added to a web server through an SMTP module to enhance error reporting or to allow developers to add SMTP functionality to their applications. 

Any modules used by the web server that queue data before transmission must maintain the confidentiality and integrity of the information before the data is transmitted.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. If the directive is omitted or is not set to "On", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. Set the "SSLFIPS" directive to "On", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23248r415278_chk'
  tag severity: 'medium'
  tag gid: 'V-221533'
  tag rid: 'SV-221533r879812_rule'
  tag stig_id: 'OH12-1X-000325'
  tag gtitle: 'SRG-APP-000441-WSR-000181'
  tag fix_id: 'F-23237r415279_fix'
  tag 'documentable'
  tag legacy: ['SV-79057', 'V-64567']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end

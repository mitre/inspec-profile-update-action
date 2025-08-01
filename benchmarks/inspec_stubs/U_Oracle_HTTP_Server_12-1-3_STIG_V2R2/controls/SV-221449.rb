control 'SV-221449' do
  title 'The version of the OHS installation must be vendor-supported.'
  desc 'Many vulnerabilities are associated with older versions of software.  As hot fixes and patches are issued, these solutions are included in the next version of the server software.  Maintaining OHS at a current version makes the efforts of a malicious user to exploit the web service more difficult.'
  desc 'check', '1. Obtain the version of the OHS 12c software (e.g., grep Oracle-HTTP-Server-12c $DOMAIN_HOME/servers/<componentName>/logs/ohs1.log). Confirm it is 12.1.3.

2. Refer to the support date schedule for "Fusion Middleware 12c (12.1.x)" at http://www.oracle.com/us/support/library/lifetime-support-middleware-069163.pdf. Confirm that support remains available and that the organization is current with respect to payments.

3. If not, this is a finding.'
  desc 'fix', '1. Install or upgrade to a version of OHS that is within the support timeframes for "Fusion Middleware 12c" at http://www.oracle.com/us/support/library/lifetime-support-middleware-069163.pdf.

2. Confirm that the organization is current with respect to support payments.'
  impact 0.7
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23164r415030_chk'
  tag severity: 'high'
  tag gid: 'V-221449'
  tag rid: 'SV-221449r879887_rule'
  tag stig_id: 'OH12-1X-000211'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23153r415031_fix'
  tag 'documentable'
  tag legacy: ['SV-79151', 'V-64661']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

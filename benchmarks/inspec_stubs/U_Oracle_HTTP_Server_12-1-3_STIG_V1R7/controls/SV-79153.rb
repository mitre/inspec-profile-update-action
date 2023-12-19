control 'SV-79153' do
  title 'OHS must be certified with accompanying Fusion Middleware products.'
  desc 'OHS is capable of being used with other Oracle products.  For the products to work properly and not introduce vulnerabilities or errors, Oracle certifies which versions work with each other.  Insisting that the certified versions be installed together in a production environment reduces the possibility of successful attacks, DoS through software system downtime and easier patch management for the SA.'
  desc 'check', '1. If OHS is used with other Fusion Middleware products, check to see if the combination is certified per http://www.oracle.com/technetwork/middleware/fusion-middleware/documentation/fmw-1213certmatrix-2226694.xls.

2. If not a certified configuration, this is a finding.'
  desc 'fix', 'Upgrade or patch OHS or other Oracle Fusion Middleware products to achieve a certified configuration per http://www.oracle.com/technetwork/middleware/fusion-middleware/documentation/fmw-1213certmatrix-2226694.xls.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65405r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64663'
  tag rid: 'SV-79153r1_rule'
  tag stig_id: 'OH12-1X-000212'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70593r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

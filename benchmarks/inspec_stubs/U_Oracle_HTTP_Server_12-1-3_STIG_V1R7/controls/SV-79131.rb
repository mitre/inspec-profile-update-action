control 'SV-79131' do
  title 'The OHS htdocs directory must not contain any default files.'
  desc 'Default files from the OHS installation should not be part of the htdocs directory.  These files are not always patched or supported and may become an attacker vector in the future.'
  desc 'check', '1. cd $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/ohs1/htdocs

2. Check for the existence of the OracleHTTPServer12c_files directory (e.g., ls).

3. If there is an OracleHTTPServer12c_files directory exists, this is a finding.'
  desc 'fix', '1. cd $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/ohs1/htdocs

2. rm –rf OracleHTTPServer12c_files.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65383r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64641'
  tag rid: 'SV-79131r1_rule'
  tag stig_id: 'OH12-1X-000201'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70571r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

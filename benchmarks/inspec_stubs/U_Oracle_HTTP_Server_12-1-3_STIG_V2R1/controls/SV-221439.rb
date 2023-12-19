control 'SV-221439' do
  title 'The OHS htdocs directory must not contain any default files.'
  desc 'Default files from the OHS installation should not be part of the htdocs directory.  These files are not always patched or supported and may become an attacker vector in the future.'
  desc 'check', '1. cd $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/ohs1/htdocs

2. Check for the existence of the OracleHTTPServer12c_files directory (e.g., ls).

3. If there is an OracleHTTPServer12c_files directory exists, this is a finding.'
  desc 'fix', '1. cd $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/ohs1/htdocs

2. rm –rf OracleHTTPServer12c_files.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23154r415000_chk'
  tag severity: 'medium'
  tag gid: 'V-221439'
  tag rid: 'SV-221439r415002_rule'
  tag stig_id: 'OH12-1X-000201'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23143r415001_fix'
  tag 'documentable'
  tag legacy: ['SV-79131', 'V-64641']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

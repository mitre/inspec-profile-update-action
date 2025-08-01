control 'SV-242169' do
  title 'To protect against unauthorized data mining, the TPS must prevent SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks that use unauthorized data mining techniques to attack databases may result in the compromise of information.

SQL injection attacks are the most prevalent attacks against web applications and databases. These attacks inject SQL commands that can read, modify, or compromise the meaning of the original SQL query. An attacker can spoof identity; expose, tamper, destroy, or make existing data unavailable; or gain unauthorized privileges on the database server.

TPS component(s) with the capability to prevent SQL code injections must be included in the IDPS implementation to protect against unauthorized data mining. These components must include rules and anomaly detection algorithms to monitor for SQL injection attacks.'
  desc 'check', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Search". 
4. Under "Filter criteria", select all "Filter categories". Select the "Filter Name" section and type "database".

If the filter settings are not set for each to "Use Category Settings" or there are filter items disabled that are outside of recommended Trend Micro settings, this is a finding.

Note: If the site has set up a security profile (i.e., not using the default profile), then this should be inspected using the site's SSP for compliance.)
  desc 'fix', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Search". 
4. Under "Filter criteria", select all "Filter categories". Select the "Filter Name" section and type "database". 
5. Ensure all items in the search results have "Use Category Settings" selected.

Note: If the site has set up a security profile (i.e., not using the default profile), then this should be inspected using the site's SSP for compliance.)
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45444r838199_chk'
  tag severity: 'medium'
  tag gid: 'V-242169'
  tag rid: 'SV-242169r839142_rule'
  tag stig_id: 'TIPP-IP-000030'
  tag gtitle: 'SRG-NET-000318-IDPS-00183'
  tag fix_id: 'F-45402r838200_fix'
  tag 'documentable'
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end

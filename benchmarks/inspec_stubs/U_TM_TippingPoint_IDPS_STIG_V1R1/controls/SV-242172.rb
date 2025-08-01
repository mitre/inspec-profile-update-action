control 'SV-242172' do
  title 'To protect against unauthorized data mining, the TPS must detect SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks that use unauthorized data mining techniques to attack databases may result in the compromise of information.

SQL injection attacks are the most prevalent attacks against web applications and databases. These attacks inject SQL commands that can read, modify, or compromise the meaning of the original SQL query. An attacker can spoof identity; expose, tamper, destroy, or make existing data unavailable; or gain unauthorized privileges on the database server.

TPS component(s) with anomaly detection must be included in the IDPS implementation to monitor for and detect unauthorized data mining. These components must include rules and anomaly detection algorithms to monitor for SQL injection attacks.'
  desc 'check', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Search". 
4. Under "Filter criteria", select all "Filter categories". Select the "Filter Name" section and type "database". 

If the filter settings are not set for each to "Use Category Settings" or there are filter items disabled that are outside of recommended Trend Micro settings, this is a finding.)
  desc 'fix', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Search". 
4. Under "Filter criteria", select all "Filter categories". Select the "Filter Name" section and type "database". 
5. Ensure all items in the search results have "Use Category Settings" selected.)
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45447r710057_chk'
  tag severity: 'medium'
  tag gid: 'V-242172'
  tag rid: 'SV-242172r710059_rule'
  tag stig_id: 'TIPP-IP-000060'
  tag gtitle: 'SRG-NET-000319-IDPS-00186'
  tag fix_id: 'F-45405r710058_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end

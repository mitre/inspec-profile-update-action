control 'SV-242171' do
  title 'To protect against unauthorized data mining, the TPS must detect code injection attacks launched against application objects including, at a minimum, application URLs and application code.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks that use unauthorized data mining techniques to attack applications may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. These attacks include buffer overrun, XML, JavaScript, and HTML injections.

TPS component(s) with anomaly detection must be included in the IDPS implementation. These components must include rules and anomaly detection algorithms to monitor for atypical application behavior, commands, and accesses.'
  desc 'check', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Search". 
4. Under "Filter criteria", select all "Filter categories". Select the "Filter Name" section and type "database", and select HTTP under "Filter Taxonomy Criteria as the Protocol". 

If the filter settings are not set for each to "Use Category Settings" or there are filter items disabled that are outside of recommended Trend Micro settings, this is a finding.

Note: If the site has set up a security profile (i.e., not using the default profile), then this should be inspected using the site's SSP for compliance.)
  desc 'fix', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Search". 
4. Under "Filter criteria", select all "Filter categories". Select the "Filter Name" section and type "database", and select HTTP under "Filter Taxonomy Criteria as the Protocol". 
5. Ensure all items in the search results have "Use Category Settings" selected.

Note: If the site has set up a security profile (i.e., not using the default profile), then this should be inspected using the site's SSP for compliance.)
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45446r838205_chk'
  tag severity: 'medium'
  tag gid: 'V-242171'
  tag rid: 'SV-242171r839144_rule'
  tag stig_id: 'TIPP-IP-000050'
  tag gtitle: 'SRG-NET-000319-IDPS-00185'
  tag fix_id: 'F-45404r838206_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end

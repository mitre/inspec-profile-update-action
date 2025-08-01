control 'SV-242177' do
  title 'The TPS must provide audit record generation capability for events where communication traffic is blocked or restricted based on policy filters, rules, signatures, and anomaly analysis.'
  desc 'To support the centralized analysis capability, the IDPS components must be able to provide the information in a format (e.g., Syslog) that can be extracted and used, allowing the application to effectively review and analyze the log records.'
  desc 'check', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Search". 
4. Under "Filter criteria", select all "Filter categories". Select the "Additional Criteria" section. 
5. Uncheck "permit" and "rate limit", then click Search. 
6. Once the results are presented, check the "Action Set" column to filter by action type. 

If any items state "Block" but not "Block/Notify", this is a finding.)
  desc 'fix', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Search". 
4. Under "Filter criteria", select all "Filter categories". Select the "Additional Criteria" section. 
5. Uncheck "permit" and "rate limit", then click "Search". 
6. Once the results are presented, click the "Action Set" column to filter by action type. If any items state "Block": 
   a. Double-click the item. 
   b. Click the radio button for "User Filter settings". 
   c. On the drop down-menu, select "Block + Notify". 
   d. Click "OK". 
   e. Once under an approved change window, click distribute and send the updated policy to all TPS systems and managed segment-groups. 
   f. Ensure progress completes at 100%.)
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45452r710072_chk'
  tag severity: 'medium'
  tag gid: 'V-242177'
  tag rid: 'SV-242177r710074_rule'
  tag stig_id: 'TIPP-IP-000110'
  tag gtitle: 'SRG-NET-000113-IDPS-00082'
  tag fix_id: 'F-45410r710073_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end

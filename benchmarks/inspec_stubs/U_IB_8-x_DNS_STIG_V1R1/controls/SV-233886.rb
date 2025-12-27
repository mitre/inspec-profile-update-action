control 'SV-233886' do
  title 'The Infoblox system must display the appropriate security classification information.'
  desc 'Configuration of the informational banner displays the security classification of the Infoblox system using both color and text. Text may be added for additional security markings.'
  desc 'check', '1. Log on to the Infoblox Grid Master or stand-alone system. 
2. The appropriate security classification color and text must be displayed on the top of each configuration screen. 
3. The output will also contain the text "Dynamic Page - Highest Possible Classification Is" and a colored bar associated with the classification. 
4. Additional text may appear if configured by the administrator. 

If the security classification color and text are not displayed at the top of each configuration screen, this is a finding.'
  desc 'fix', '1. Navigate to Grid >> Grid Manager >> Grid Properties, or System >> System Manager >> System Properties if using a stand-alone configuration.  
2. Select the "Security", "Advanced" tab. Click "Enable Security Banner". 
3. Use the drop-down menus to select the Security Level and Security Level Color appropriate for each level. 
4. Additional text can be entered if required by DoD or local policy.  
5. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
6. Administrators should log out and close the web browser. 
7. It may be necessary to clear the web browser cache for the banner to display or update on a session opened shortly after reconfiguration.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37071r611178_chk'
  tag severity: 'medium'
  tag gid: 'V-233886'
  tag rid: 'SV-233886r621666_rule'
  tag stig_id: 'IDNS-8X-400028'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-37036r611179_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

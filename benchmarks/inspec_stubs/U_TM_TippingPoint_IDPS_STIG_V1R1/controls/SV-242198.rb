control 'SV-242198' do
  title 'The TPS must block malicious code.'
  desc 'Configuring the TPS to delete and/or quarantine based on local organizational incident handling procedures minimizes the impact of this code on the network.'
  desc 'check', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Edit Details". Ensure the deployment mode of "Security-Optimized" is selected. The security-optimized deployment mode ensures all strict DoD vulnerabilities are blocked and alerted upon. 
4. Navigate to "Profile Overview" and ensure the action set for each category is set to "Recommended". The recommended action set is set to ensure all suspicious and vulnerable traffic is blocked and alerted upon. 

If the "security-optimized" deployment mode is not configured, this is a finding.)
  desc 'fix', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Edit Details". Select the deployment mode of "Security-Optimized". The security-optimized deployment mode ensures all strict DoD vulnerabilities are blocked and alerted upon.
4. Navigate to "Profile Overview", and select the action set for each category to "Recommended". The recommended action set is set to ensure all suspicious and vulnerable traffic is blocked and alerted upon.)
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45473r710135_chk'
  tag severity: 'medium'
  tag gid: 'V-242198'
  tag rid: 'SV-242198r710137_rule'
  tag stig_id: 'TIPP-IP-000350'
  tag gtitle: 'SRG-NET-000249-IDPS-00176'
  tag fix_id: 'F-45431r710136_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end

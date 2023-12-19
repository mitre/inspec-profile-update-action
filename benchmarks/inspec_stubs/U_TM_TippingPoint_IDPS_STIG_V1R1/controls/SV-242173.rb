control 'SV-242173' do
  title 'The Trend Micro TippingPoint Security Management System (SMS) must be configured to send security IPS policy to the Trend Micro Threat Protection System (TPS).'
  desc 'The flow of all communications traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data.

Restricting the flow of communications traffic, also known as Information flow control, regulates where information is allowed to travel as opposed to who is allowed to access the information and without explicit regard to subsequent accesses to that information.

The Trend Micro SMS will include policy filters, rules, signatures, and behavior analysis algorithms that inspects and restricts traffic based on the characteristics of the information and/or the information path as it crosses internal network boundaries. The Trend Micro SMS monitors for harmful or suspicious information flows and restricts or blocks this traffic based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'check', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Edit Details". Ensure the deployment mode of "Security-Optimized" is selected. The security-optimized deployment mode ensures all strict DoD vulnerabilities are blocked and alerted upon. 
4. Navigate to "Profile Overview" and ensure the action set for each category is set to "Recommended". The recommended action set is set to ensure all suspicious and vulnerable traffic is blocked and alerted upon. 

If the "security-optimized" deployment mode is not configured, this is a finding.)
  desc 'fix', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile.
2. If there is no profile configured, select "default". 
3. Click "Edit Details". Select the deployment mode of "Security-Optimized". The security-optimized deployment mode ensures all strict DoD vulnerabilities are blocked and alerted upon. 
4. Navigate to "Profile Overview", and select the action set for each category to "Recommended". The recommended action set is set to ensure all suspicious and vulnerable traffic is blocked and alerted upon.)
  impact 0.7
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45448r710060_chk'
  tag severity: 'high'
  tag gid: 'V-242173'
  tag rid: 'SV-242173r710062_rule'
  tag stig_id: 'TIPP-IP-000070'
  tag gtitle: 'SRG-NET-000018-IDPS-00018'
  tag fix_id: 'F-45406r710061_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end

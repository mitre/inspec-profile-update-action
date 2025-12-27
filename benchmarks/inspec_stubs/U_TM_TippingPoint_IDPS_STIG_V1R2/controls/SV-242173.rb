control 'SV-242173' do
  title 'The Trend Micro TippingPoint Security Management System (SMS) must be configured to send security IPS policy to the Trend Micro Threat Protection System (TPS).'
  desc 'The flow of all communications traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data.

Restricting the flow of communications traffic, also known as Information flow control, regulates where information is allowed to travel as opposed to who is allowed to access the information and without explicit regard to subsequent accesses to that information.

The Trend Micro SMS will include policy filters, rules, signatures, and behavior analysis algorithms that inspects and restricts traffic based on the characteristics of the information and/or the information path as it crosses internal network boundaries. The Trend Micro SMS monitors for harmful or suspicious information flows and restricts or blocks this traffic based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'check', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Edit Details". Ensure the deployment mode of "Default" is selected. The default deployment mode ensures all strict DoD vulnerabilities are blocked and alerted upon. 
4. Navigate to "Profile Overview" and ensure the action set for each category is set to "Recommended". The recommended action set is set to ensure all suspicious and vulnerable traffic is blocked and alerted upon. 

If the "default" deployment mode is used, but not configured in a compliant manner, this is a finding.

Note: If the site has set up a security profile (i.e., not using the default profile), then verify compliance with the site's SSP requirements.)
  desc 'fix', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile.
2. If there is no profile configured, select "default". 
3. Click "Edit Details". Select the deployment mode of "Default". The default deployment mode ensures all strict DoD vulnerabilities are blocked and alerted upon. 
4. Navigate to "Profile Overview", and select the action set for each category to "Recommended". The recommended action set is set to ensure all suspicious and vulnerable traffic is blocked and alerted upon.
5. Go through each default rule and tune the block and disabled rules to ensure they reflect the network environment's traffic patterns. Not all default block or disabled rules may be applicable to all DoD networks, especially in the cases of multitenancy.

Note: If the site has set up a security profile (i.e., not using the default profile), then verify compliance using the site's SSP.)
  impact 0.7
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45448r840497_chk'
  tag severity: 'high'
  tag gid: 'V-242173'
  tag rid: 'SV-242173r840498_rule'
  tag stig_id: 'TIPP-IP-000070'
  tag gtitle: 'SRG-NET-000018-IDPS-00018'
  tag fix_id: 'F-45406r840496_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end

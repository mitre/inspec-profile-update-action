control 'SV-242202' do
  title 'The IDPS must generate an alert to the ISSM and ISSO, at a minimum, when unauthorized network services are detected.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore may be unreliable or serve as malicious rogues for valid services.

Automated mechanisms can be used to send automatic alerts or notifications. Such automatic alerts or notifications can be conveyed in a variety of ways (e.g., telephonically, via electronic mail, via text message, or via websites).

The IDPS must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. The ISSM or ISSO may designate the system administrator or other authorized personnel to receive the alert within the specified time, validate the alert, then forward only validated alerts to the ISSO to the vulnerability discussion.'
  desc 'check', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Edit Details". Ensure the deployment mode of "Security-Optimized" is selected. The security-optimized deployment mode ensures all strict DoD vulnerabilities are blocked and alerted upon. 
4. Navigate to "Profile Overview" and ensure the action set for each category is set to "Recommended". The recommended action set is set to ensure all suspicious and vulnerable traffic is blocked and alerted upon. 

If the "security-optimized" deployment mode is not configured, this is a finding.)
  desc 'fix', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Edit Details". Select the deployment mode of "Security-Optimized". The security-optimized deployment mode ensures all strict DoD vulnerabilities are blocked and alerted upon. 
4. Navigate to "Profile Overview" and select the action set for each category to "Recommended". The recommended action set is set to ensure all suspicious and vulnerable traffic is blocked and alerted upon.)
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45477r710147_chk'
  tag severity: 'medium'
  tag gid: 'V-242202'
  tag rid: 'SV-242202r710149_rule'
  tag stig_id: 'TIPP-IP-000400'
  tag gtitle: 'SRG-NET-000385-IDPS-00211'
  tag fix_id: 'F-45435r710148_fix'
  tag 'documentable'
  tag cci: ['CCI-002684']
  tag nist: ['SI-4 (22) (b)']
end

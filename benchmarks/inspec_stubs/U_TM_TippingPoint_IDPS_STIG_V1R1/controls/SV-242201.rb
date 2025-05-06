control 'SV-242201' do
  title 'The TPS must detect network services that have not been authorized or approved by the ISSO or ISSM, at a minimum, through use of a site-approved TPS device profile.'
  desc 'Unauthorized or unapproved network services lack organizational verification or validation and therefore may be unreliable or serve as malicious rogues for valid services. 

Examples of network services include service-oriented architectures (SOAs), cloud-based services (e.g., infrastructure as a service, platform as a service, or software as a service), cross-domain, Voice Over Internet Protocol, Instant Messaging, auto-execute, and file sharing.

To comply with this requirement, the IDPS may be configured to detect services either directly or indirectly (i.e., by detecting traffic associated with a service).'
  desc 'check', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile.
2. If there is not one configured, select "Default". 
3. Click "Edit Details". Ensure the deployment mode of "Security-Optimized" is selected. The security-optimized deployment mode ensures all strict DoD vulnerabilities are blocked and alerted upon.
4. Navigate to "Profile Overview" and ensure the action set for each category is set to "Recommended". The recommended action set is set to ensure all suspicious and vulnerable traffic is blocked and alerted upon. 

If the "security-optimized" deployment mode is not configured, this is a finding.)
  desc 'fix', %q(1. In the Trend Micro SMS, navigate to "Profiles" and "Inspection Profiles" and select the organization's profile. 
2. If there is not one configured, select "Default". 
3. Click "Edit Details"; select the deployment mode of "Security-Optimized". The security-optimized deployment mode ensures all strict DoD vulnerabilities are blocked and alerted upon. 
4. Navigate to "Profile Overview" and select the action set for each category to "Recommended". The recommended action set is set to ensure all suspicious and vulnerable traffic is blocked and alerted upon.)
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45476r710144_chk'
  tag severity: 'medium'
  tag gid: 'V-242201'
  tag rid: 'SV-242201r710146_rule'
  tag stig_id: 'TIPP-IP-000380'
  tag gtitle: 'SRG-NET-000384-IDPS-00209'
  tag fix_id: 'F-45434r710145_fix'
  tag 'documentable'
  tag cci: ['CCI-002683']
  tag nist: ['SI-4 (22) (a)']
end

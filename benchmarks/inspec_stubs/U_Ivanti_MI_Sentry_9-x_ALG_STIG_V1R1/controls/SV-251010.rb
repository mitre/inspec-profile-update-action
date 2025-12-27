control 'SV-251010' do
  title 'The Sentry must restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. Blocking or restricting detected harmful or suspicious communications between interconnected networks enforces approved authorizations for controlling the flow of traffic.

This requirement applies to the flow of information between the Sentry when used as a gateway or boundary device which allows traffic flow between interconnected networks of differing security policies.

The Sentry and MobileIron UEM must be configured with policy filters (e.g., security policy and compliance rules) that restrict or block information system services.'
  desc 'check', 'Verify the Sentry restricts or blocks harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on mobile device security posture reported by the MobileIron UEM.

1. Log in to the Core Admin Portal.
2. Go to Policies and Configurations >> Policies. 
3. Verify the appropriate Security Policies are applied to the devices accessing systems behind the Sentry.
4. Click "Edit".
5. In the Access Control section of the policy, verify the Block Email and AppConnect apps compliance action is selected for the "when a compromised device is detected" control for the iOS and Android device operating systems sections.
6. Click "Cancel".

If "when a compromised device is detected" control for the iOS and Android device operating systems is not selected in the Access control section, this is a finding.'
  desc 'fix', 'Configure the Sentry to restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

1. Log in to the Core Admin Portal.
2. Go to Policies and Configurations >> Policies. 
3. Ensure the appropriate Security Policies are applied to the devices accessing systems behind the Sentry.
4. Click "Edit".
5. In the Access Control section of the policy, select the Block Email and AppConnect apps compliance for the “when a compromised device is detected” control for the iOS and Android device operating systems sections. 
6. Click "Save".

Refer to the MobileIron Sentry 9.8.0 Guide on how to configure the specific Sentry Services.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54445r802611_chk'
  tag severity: 'medium'
  tag gid: 'V-251010'
  tag rid: 'SV-251010r802252_rule'
  tag stig_id: 'MOIS-AL-000030'
  tag gtitle: 'SRG-NET-000019-ALG-000018'
  tag fix_id: 'F-54399r802251_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end

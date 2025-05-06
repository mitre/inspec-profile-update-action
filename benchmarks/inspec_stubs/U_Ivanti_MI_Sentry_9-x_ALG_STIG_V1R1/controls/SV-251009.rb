control 'SV-251009' do
  title 'The Sentry must enforce approved authorizations for controlling the flow of information within the network based on attribute-based inspection of the source, destination, and headers, of the communications traffic.'
  desc 'Information flow control regulates where information is allowed to travel within a network. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data.

Sentry enforces approved authorizations by employing security policy and/or rules configured in MobileIron UEM that restrict information system services capability based on header or protocol information.'
  desc 'check', 'Verify the Sentry and MobileIron UEM is configured to enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

MobileIron UEM applies Configurations to devices/users based on manual or dynamic labels. Verify that Configurations that leverage Sentry such as Email, VPN, Docs@Work, or any backend service which leverage Sentry as a gateway are applied to the appropriate user groups via the configurable labels. If not, this is a finding. 

1. Log in to the Core Admin Portal. 
2. Go to Policies and Configurations >> Configurations. 
3. Verify the Sentry related Configurations are applied to the devices accessing systems behind the Sentry.

If Configurations are misassigned to the wrong label/user groups, this is a finding.'
  desc 'fix', 'Configure the Sentry to enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic via MI Core labels. 

1. Log in to the Core Admin Portal. 
2. Go to Policies and Configurations >> Configurations.
3. For Active Sync email use cases with Sentry, apply the Exchange or mail app configurations using the Sentry to devices via a label.
4. For App Tunnel use cases, apply app configurations using the Sentry to device via a label.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54444r802247_chk'
  tag severity: 'medium'
  tag gid: 'V-251009'
  tag rid: 'SV-251009r802249_rule'
  tag stig_id: 'MOIS-AL-000020'
  tag gtitle: 'SRG-NET-000018-ALG-000017'
  tag fix_id: 'F-54398r802248_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end

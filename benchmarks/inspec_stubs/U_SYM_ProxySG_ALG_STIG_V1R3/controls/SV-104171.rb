control 'SV-104171' do
  title 'If Symantec ProxySG filters externally initiated traffic, reverse proxy services must be configured.'
  desc "Automated monitoring of remote access traffic allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by inspecting connection activities of remote access capabilities.

Remote access methods include both unencrypted and encrypted traffic (e.g., web portals, web content filter, TLS, and webmail). With inbound TLS inspection, the traffic must be inspected prior to being allowed on the enclave's web servers hosting TLS or HTTPS applications."
  desc 'check', 'The ProxySG is designed to monitor and control inbound traffic when in a reverse proxy configuration. Verify this is configured.

1. Verify with the ProxySG administrator that reverse proxy services are configured. 
2. Log on to the Web Management Console. 
3. Click Configuration >> Services >> Proxy Services. 
4. Review each reverse proxy service identified by the administrator and Verify that all organizational services are represented by an HTTP or HTTPS proxy service in the configuration.

If Symantec ProxySG filters externally initiated traffic but reverse proxy services are not configured, this is a finding.'
  desc 'fix', 'Configure the ProxySG to monitor and control inbound traffic by configuring reverse proxy services. This provides SSL proxy in reverse proxy mode.

1. Log on to the Web Management Console. 
2. Click Configuration >> Services >> Proxy Services. 
3. Click "New Service".
4. Enter information into the various service boxes in accordance with site architecture, operational requirements, and SSP requirements for which web servers are to be monitored and controlled.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93403r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94217'
  tag rid: 'SV-104171r1_rule'
  tag stig_id: 'SYMP-AG-000010'
  tag gtitle: 'SRG-NET-000061-ALG-000009'
  tag fix_id: 'F-100333r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end

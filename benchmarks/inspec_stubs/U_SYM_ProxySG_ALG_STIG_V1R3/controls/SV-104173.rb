control 'SV-104173' do
  title 'Symantec ProxySG providing intermediary services for remote access communications traffic must ensure outbound traffic is monitored for compliance with remote access security policies.'
  desc 'Automated monitoring of remote access traffic allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by inspecting connection activities of remote access capabilities.

Remote access methods include both unencrypted and encrypted traffic (e.g., web portals, web content filter, TLS, and webmail). With outbound traffic inspection, traffic must be inspected prior to being forwarded to destinations outside of the enclave, such as external email traffic.'
  desc 'check', 'Verify the ProxySG is configured to inspect internally initiated traffic.

1. Log on to the Web Management Console. 
2. Click Configuration >> Visual Policy Manager. 
3. Click "Launch". While in the Visual Policy Manager, verify that at least one SSL Access Layer (transparent proxy architectures) or Web Access Layer (explicit proxy architectures) is configured.

If the ProxySG is not configured to inspect internally initiated traffic, this is a finding.'
  desc 'fix', 'Configure the ProxySG to inspect internally initiated traffic.

1. Log on to the Web Management Console.
2. Click Configuration >> Visual Policy Manager.
3. Click "Launch". While in the Visual Policy Manager, click Policy >> Add SSL Access Layer (transparent proxy architectures) or Add Web Access Layer (explicit proxy architectures).
4. Click File >> Install Policy on SG Appliance.'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93405r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94219'
  tag rid: 'SV-104173r1_rule'
  tag stig_id: 'SYMP-AG-000020'
  tag gtitle: 'SRG-NET-000061-ALG-000009'
  tag fix_id: 'F-100335r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end

control 'SV-253282' do
  title 'Inbound exceptions to the firewall on Windows 11 domain workstations must only allow authorized remote management hosts.'
  desc 'Allowing inbound access to domain workstations from other systems may allow lateral movement across systems if credentials are compromised. Limiting inbound connections only from authorized remote management systems will help limit this exposure.'
  desc 'check', 'Verify firewall exceptions to inbound connections on domain workstations include only authorized remote management hosts.

If allowed inbound exceptions are not limited to authorized remote management hosts, this is a finding.

Review inbound firewall exceptions.
Computer Configuration >> Windows Settings >> Security Settings >> Windows Defender Firewall with Advanced Security >> Windows Defender Firewall with Advanced Security >> Inbound Rules (this link will be in the right pane)

For any inbound rules that allow connections view the Scope for Remote IP address. This may be defined as an IP address, subnet, or range. The rule must apply to all firewall profiles.

If a third-party firewall is used, ensure comparable settings are in place.'
  desc 'fix', 'Configure firewall exceptions to inbound connections on domain workstations to include only authorized remote management hosts.

Configure only inbound connection exceptions for authorized remote management hosts.
Computer Configuration >> Windows Settings >> Security Settings >> Windows Defender Firewall with Advanced Security >> Windows Defender Firewall with Advanced Security >> Inbound Rules (this link will be in the right pane)

For any inbound rules that allow connections, configure the Scope for Remote IP address to those of authorized remote management hosts. This may be defined as an IP address, subnet or range. Apply the rule to all firewall profiles.

If a third-party firewall is used, configure inbound exceptions to only include authorized remote management hosts.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56735r828928_chk'
  tag severity: 'medium'
  tag gid: 'V-253282'
  tag rid: 'SV-253282r828930_rule'
  tag stig_id: 'WN11-00-000140'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag fix_id: 'F-56685r828929_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

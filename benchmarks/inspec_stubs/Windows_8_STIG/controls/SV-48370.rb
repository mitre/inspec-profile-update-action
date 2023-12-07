control 'SV-48370' do
  title 'Inbound exceptions to the firewall on domain workstations must only allow authorized remote management hosts.'
  desc 'Allowing inbound access to domain workstations from other systems may allow lateral movement across systems if credentials are compromised.  Limiting inbound connections only from authorized remote management systems will help limit this exposure.'
  desc 'check', 'Verify firewall exceptions to inbound connections on domain workstations include only authorized remote management hosts.

If allowed inbound exceptions are not limited to authorized remote management hosts, this is a finding.

Review inbound firewall exceptions.
Computer Configuration -> Windows Settings -> Security Settings -> Windows Firewall with Advanced Security -> Windows Firewall with Advanced Security -> Inbound Rules (this link will be in the right pane) -> 

For any inbound rules that allow connections view the Scope for Remote IP address.  This may be defined as an IP address, subnet, or range.  The rule must apply to all firewall profiles.

If a third-party firewall is used, ensure comparable settings are in place.'
  desc 'fix', 'Configure firewall exceptions to inbound connections on domain workstations to include only authorized remote management hosts.

Configure only inbound connection exceptions for authorized remote management hosts.
Computer Configuration -> Windows Settings -> Security Settings -> Windows Firewall with Advanced Security -> Windows Firewall with Advanced Security -> Inbound Rules (this link will be in the right pane) -> 

For any inbound rules that allow connections, configure the Scope for Remote IP address to those of authorized remote management hosts.  This may be defined as an IP address, subnet or range.  Apply the rule to all firewall profiles.

If a third-party firewall is used, configure inbound exceptions to only include authorized remote management hosts.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45039r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36440'
  tag rid: 'SV-48370r2_rule'
  tag stig_id: 'WN08-FW-000100'
  tag gtitle: 'Inbound Firewall Exception for Administration'
  tag fix_id: 'F-41501r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end

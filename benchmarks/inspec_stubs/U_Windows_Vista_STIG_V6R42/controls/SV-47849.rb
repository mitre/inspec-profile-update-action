control 'SV-47849' do
  title 'Inbound exceptions to the firewall on domain workstations must only allow authorized management systems and remote management hosts.'
  desc 'Allowing inbound access to domain workstations from other systems may allow lateral movement across systems if credentials are compromised.  Limiting inbound connections only from authorized management systems and remote management hosts will help limit this exposure.'
  desc 'check', 'Verify firewall exceptions for inbound connections on domain workstations only allow authorized management systems and remote management hosts.

Review inbound firewall exception rules in Windows Firewall with Advanced Security.  Firewall rules can be complex and should be reviewed with the firewall administrator.

One method for restricting inbound connections is to only allow exceptions for a specific scope of remote IP addresses.

If allowed inbound exceptions are not limited to authorized management systems and remote management hosts, this is a finding.

If a third-party firewall is used, ensure comparable settings are in place.'
  desc 'fix', 'Ensure firewall exceptions to inbound connections on domain workstations only allow authorized management systems and remote management hosts.

Firewall rules can be complex and should be thoroughly tested be applying in a production environment.

One method for restricting inbound connections is to only allow exceptions for a specific scope of remote IP addresses.  For any inbound rules that allow connections from other systems, configure the Scope for Remote IP address to those of authorized management systems and remote management hosts. This may be defined as an IP address, subnet or range. Apply the rule to all firewall profiles.

If a third-party firewall is used, configure inbound exceptions to only include authorized remote management hosts.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-44688r2_chk'
  tag severity: 'medium'
  tag gid: 'V-36440'
  tag rid: 'SV-47849r1_rule'
  tag stig_id: 'WINFW-000100'
  tag gtitle: 'Inbound Firewall Exception for Administration'
  tag fix_id: 'F-40975r4_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

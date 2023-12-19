control 'SV-242009' do
  title 'Inbound exceptions to the firewall on domain workstations must only allow authorized remote management hosts.'
  desc 'Allowing inbound access to domain workstations from other systems may allow lateral movement across systems if credentials are compromised.  Limiting inbound connections only from authorized remote management systems will help limit this exposure.'
  desc 'check', 'This requirement is NA for servers and non domain workstations.

Verify firewall exceptions for inbound connections on domain workstations only allow authorized management systems and remote management hosts.

Review inbound firewall exception rules in Windows Firewall with Advanced Security. Firewall rules can be complex and should be reviewed with the firewall administrator.

One method for restricting inbound connections is to only allow exceptions for a specific scope of remote IP addresses.

If allowed inbound exceptions are not limited to authorized management systems and remote management hosts, this is a finding.'
  desc 'fix', 'Ensure firewall exceptions to inbound connections on domain workstations only allow authorized management systems and remote management hosts.

Firewall rules can be complex and should be thoroughly tested before applying in a production environment.

One method for restricting inbound connections is to only allow exceptions for a specific scope of remote IP addresses. For any inbound rules that allow connections from other systems, configure the Scope for Remote IP addresses to those of authorized management systems and remote management hosts. This may be defined as an IP address, subnet, or range. Apply the rule to all firewall profiles.'
  impact 0.5
  ref 'DPMS Target Windows Firewall with Advanced Security'
  tag check_id: 'C-45284r698266_chk'
  tag severity: 'medium'
  tag gid: 'V-242009'
  tag rid: 'SV-242009r698268_rule'
  tag stig_id: 'WNFWA-000100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-45243r698267_fix'
  tag 'documentable'
  tag legacy: ['V-36440', 'SV-55086']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end

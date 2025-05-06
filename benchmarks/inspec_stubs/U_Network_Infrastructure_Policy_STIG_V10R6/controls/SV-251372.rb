control 'SV-251372' do
  title 'A dedicated management network must be implemented.'
  desc 'To deploy a management network for the purpose of controlling, monitoring, and restricting management traffic, a separate management subnet must be implemented. Define a large enough address block that will enable the management network to scale in proportion to the managed network.'
  desc 'check', 'Review the network topology diagram to determine if a management network has been implemented. Validate the IP address space documented for this network by verifying the IP addresses referenced for management access (SSH, NTP, AAA, SNMP manager, Syslog server, etc.) to the managed network elements.

If a management network has not been implemented, this is a finding.'
  desc 'fix', 'Define a large enough address block that will enable the management network to scale in proportion to the managed network.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54807r806069_chk'
  tag severity: 'medium'
  tag gid: 'V-251372'
  tag rid: 'SV-251372r806071_rule'
  tag stig_id: 'NET0998'
  tag gtitle: 'NET0998'
  tag fix_id: 'F-54760r806070_fix'
  tag 'documentable'
  tag legacy: ['V-17772', 'SV-18981']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

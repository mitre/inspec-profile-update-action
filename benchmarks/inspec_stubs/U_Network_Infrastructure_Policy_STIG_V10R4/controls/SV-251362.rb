control 'SV-251362' do
  title 'Dynamic Host Configuration Protocol (DHCP) servers used within SIPRNet infrastructure must be configured with a minimum lease duration time of 30 days.'
  desc 'In order to trace, audit, and investigate suspicious activity, DHCP servers within the SIPRNet infrastructure must have the minimum lease duration time configured to 30 or more days.'
  desc 'check', 'Review the configuration of SIPRNet DHCP servers to verify that the lease duration is set to a minimum of thirty days.

If the lease duration is less than thirty days, this is a finding.'
  desc 'fix', 'Configure any DHCP server used on the SIPRNet with a minimum lease duration of thirty days.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54797r806039_chk'
  tag severity: 'low'
  tag gid: 'V-251362'
  tag rid: 'SV-251362r853650_rule'
  tag stig_id: 'NET0199'
  tag gtitle: 'NET0199'
  tag fix_id: 'F-54750r806040_fix'
  tag 'documentable'
  tag legacy: ['V-8100', 'SV-8586']
  tag cci: ['CCI-001902']
  tag nist: ['AU-10 (1) (b)']
end

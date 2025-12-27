control 'SV-8586' do
  title 'Dynamic Host Configuration Protocol (DHCP) servers used within SIPRNet infrastructure must be configured with a minimum lease duration time of 30 days.'
  desc 'In order to trace, audit, and investigate suspicious activity, DHCP servers within the SIPRNet infrastructure must have the minimum lease duration time configured to 30 or more days.'
  desc 'check', 'Review the configuration of SIPRNet DHCP servers to verify that the lease duration is set to a minimum of thirty days.

If the lease duration is less than thirty days, this is a finding.'
  desc 'fix', 'Configure any DHCP server used on the SIPRNet with a minimum lease duration of thirty days.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-7481r3_chk'
  tag severity: 'low'
  tag gid: 'V-8100'
  tag rid: 'SV-8586r3_rule'
  tag stig_id: 'NET0199'
  tag gtitle: 'DHCP lease duration is less than 30 days on SIPR.'
  tag fix_id: 'F-7675r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001902']
  tag nist: ['AU-10 (1) (b)']
end

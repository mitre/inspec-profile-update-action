control 'SV-37335' do
  title 'For systems using DNS resolution, at least two name servers must be configured.'
  desc 'To provide availability for name resolution services, multiple redundant name servers are mandated.  A failure in name resolution could lead to the failure of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.'
  desc 'check', 'Determine if DNS is enabled on the system.
# grep dns /etc/nsswitch.conf
If no line is returned, or any returned line is commented out, the system does not use DNS, and this is not applicable.

Determine the name servers used by the system.
# grep nameserver /etc/resolv.conf
If less than two lines are returned that are not commented out, this is a finding.'
  desc 'fix', 'Edit /etc/resolv.conf and add additional "nameserver" lines until at least two are present.'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36026r1_chk'
  tag severity: 'low'
  tag gid: 'V-22331'
  tag rid: 'SV-37335r2_rule'
  tag stig_id: 'GEN001375'
  tag gtitle: 'GEN001375'
  tag fix_id: 'F-31272r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001182']
  tag nist: ['SC-22']
end

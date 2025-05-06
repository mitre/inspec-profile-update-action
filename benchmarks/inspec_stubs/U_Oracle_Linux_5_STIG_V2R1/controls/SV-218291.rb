control 'SV-218291' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19766r568819_chk'
  tag severity: 'low'
  tag gid: 'V-218291'
  tag rid: 'SV-218291r603259_rule'
  tag stig_id: 'GEN001375'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19764r568820_fix'
  tag 'documentable'
  tag legacy: ['V-22331', 'SV-64547']
  tag cci: ['CCI-001182', 'CCI-000366']
  tag nist: ['SC-22', 'CM-6 b']
end

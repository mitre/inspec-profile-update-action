control 'SV-51525' do
  title 'The test and development infrastructure must use a DMZ to import and export data between test and development environments and DoD operational networks.'
  desc 'Most systems that reside in the test and development environment require external access using a DoD network as the transport mechanism.  Logical access control mechanisms, such as strictly controlled ACLs for both ingress and egress traffic, must be utilized at the environment boundary.  The permissible activities for test and development environments include, but are not limited to, user functional acceptance of a product, final stage testing, and development.  Downloading software from the Internet is acceptable for the environment; however, establish a DMZ for such purposes.'
  desc 'check', 'Determine whether there is a DMZ properly configured for traffic entering and leaving the test and development environment.  If a DMZ for traffic entering and leaving the test and development environment is not implemented, this is a finding.'
  desc 'fix', 'Configure and implement a DMZ for traffic entering and leaving the test and development environment.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone B'
  tag check_id: 'C-46798r2_chk'
  tag severity: 'medium'
  tag gid: 'V-39658'
  tag rid: 'SV-51525r1_rule'
  tag stig_id: 'ENTD0190'
  tag gtitle: 'ENTD0190 - Data is not transported through a DMZ.'
  tag fix_id: 'F-44633r2_fix'
  tag 'documentable'
  tag ia_controls: 'DCSP-1, EBBD-1, EBBD-2, EBBD-3, ECSC-1'
end

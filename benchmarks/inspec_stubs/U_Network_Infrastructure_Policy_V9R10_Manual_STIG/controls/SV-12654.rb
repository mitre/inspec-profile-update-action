control 'SV-12654' do
  title 'All Releasable Local Area Network (REL LAN) environments must be documented in the System Security Authorization Agreement (SSAA).'
  desc 'The ISSM will ensure Releasable Local Area Network (REL LAN) environments are documented in the SSAA.'
  desc 'check', 'Interview the ISSM and review the SSAA.  GRE tunnels found on a premise or edge SIPRNet router that have an endpoint within the REL IP address space must be documented in the SSAA.

If the REL LAN has not been documented in the SSAA, this is a finding.'
  desc 'fix', 'The ISSM will document GRE tunnels defined on a premise or edge SIPRNet router that have an endpoint within the REL IP address space.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-8118r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12101'
  tag rid: 'SV-12654r2_rule'
  tag stig_id: 'NET1815'
  tag gtitle: 'REL LAN environments are not documented in SSAA'
  tag fix_id: 'F-11390r2_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

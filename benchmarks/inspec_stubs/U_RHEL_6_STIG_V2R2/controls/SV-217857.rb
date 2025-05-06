control 'SV-217857' do
  title 'A file integrity tool must be installed.'
  desc 'The AIDE package must be installed if it is to be available for integrity checking.'
  desc 'check', 'If another file integrity tool is installed, this is not a finding.

Run the following command to determine if the "aide" package is installed: 

# rpm -q aide


If the package is not installed, this is a finding.'
  desc 'fix', 'Install the AIDE package with the command: 

# yum install aide'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19338r376586_chk'
  tag severity: 'medium'
  tag gid: 'V-217857'
  tag rid: 'SV-217857r603264_rule'
  tag stig_id: 'RHEL-06-000016'
  tag gtitle: 'SRG-OS-000363'
  tag fix_id: 'F-19336r376587_fix'
  tag 'documentable'
  tag legacy: ['V-38489', 'SV-50290']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end

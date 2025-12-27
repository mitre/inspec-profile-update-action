control 'SV-219546' do
  title 'A file integrity tool must be installed.'
  desc 'The AIDE package must be installed if it is to be available for integrity checking.'
  desc 'check', 'If another file integrity tool is installed, this is not a finding.

Run the following command to determine if the "aide" package is installed: 

# rpm -q aide

If the package is not installed, this is a finding.'
  desc 'fix', 'Install the AIDE package with the command: 

# yum install aide'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21271r358178_chk'
  tag severity: 'medium'
  tag gid: 'V-219546'
  tag rid: 'SV-219546r793803_rule'
  tag stig_id: 'OL6-00-000016'
  tag gtitle: 'SRG-OS-000363'
  tag fix_id: 'F-21270r358179_fix'
  tag 'documentable'
  tag legacy: ['SV-64921', 'V-50715']
  tag cci: ['CCI-001744']
  tag nist: ['CM-3 (5)']
end

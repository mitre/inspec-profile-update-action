control 'SV-218111' do
  title 'The Red Hat Enterprise Linux operating system must have an anti-virus solution installed.'
  desc 'Virus scanning software can be used to protect a system from penetration from computer viruses and to limit their spread through intermediate systems.'
  desc 'check', 'Verify an anti-virus solution is installed on the system. The anti-virus solution may be bundled with an approved host-based security solution.

If there is no anti-virus solution installed on the system, this is a finding.'
  desc 'fix', 'Install an anti-virus solution on the system.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19592r466210_chk'
  tag severity: 'medium'
  tag gid: 'V-218111'
  tag rid: 'SV-218111r603264_rule'
  tag stig_id: 'RHEL-06-000533'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19590r377349_fix'
  tag 'documentable'
  tag legacy: ['SV-96157', 'V-81443']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

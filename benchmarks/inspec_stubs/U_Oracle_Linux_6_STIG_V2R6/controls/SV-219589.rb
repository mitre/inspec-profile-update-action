control 'SV-219589' do
  title 'The Oracle Linux 6 operating system must use a virus scan program.'
  desc 'Virus scanning software can be used to protect a system from penetration from computer viruses and to limit their spread through intermediate systems.

The virus scanning software should be configured to perform scans dynamically on accessed files. If this capability is not available, the system must be configured to scan, at a minimum, all altered files on the system on a daily basis.

If the system processes inbound SMTP mail, the virus scanner must be configured to scan all received mail.'
  desc 'check', 'Verify an antivirus solution is installed on the system. The anti-virus solution may be bundled with an approved host-based security solution.

If there is no antivirus solution installed on the system, this is a finding.'
  desc 'fix', 'Install an antivirus solution on the system.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21314r462364_chk'
  tag severity: 'medium'
  tag gid: 'V-219589'
  tag rid: 'SV-219589r793846_rule'
  tag stig_id: 'OL6-00-000533'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21313r466211_fix'
  tag 'documentable'
  tag legacy: ['SV-96167', 'V-81453']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

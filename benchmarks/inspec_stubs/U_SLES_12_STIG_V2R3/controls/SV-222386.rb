control 'SV-222386' do
  title 'The SUSE operating system must use a virus scan program.'
  desc 'Virus scanning software can be used to protect a system from penetration from computer viruses and to limit their spread through intermediate systems. 

The virus scanning software should be configured to perform scans dynamically on accessed files. If this capability is not available, the system must be configured to scan, at a minimum, all altered files on the system on a daily basis.

If the system processes inbound SMTP mail, the virus scanner must be configured to scan all received mail.'
  desc 'check', 'Verify an anti-virus solution is installed on the system. The anti-virus solution may be bundled with an approved host-based security solution.

If there is no anti-virus solution installed on the system, this is a finding.'
  desc 'fix', 'Install an antivirus solution on the system.'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-19592r466210_chk'
  tag severity: 'high'
  tag gid: 'V-222386'
  tag rid: 'SV-222386r603262_rule'
  tag stig_id: 'SLES-12-030611'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-21313r466211_fix'
  tag 'documentable'
  tag legacy: ['V-102727', 'SV-111689']
  tag cci: ['CCI-001668']
  tag nist: ['SI-3 a']
end

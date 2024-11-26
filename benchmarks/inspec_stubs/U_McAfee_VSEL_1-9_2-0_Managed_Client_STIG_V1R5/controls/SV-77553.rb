control 'SV-77553' do
  title 'The McAfee VirusScan Enterprise for Linux 1.9.x/2.0.x must scan all media used for system maintenance prior to use.'
  desc 'Removable media such as CD/DVDs allow a path for malware to be introduced to a Linux System. It is imperative to protect Linux systems from malware introduced from removable media by ensuring they are scanned before use.'
  desc 'check', 'Consult with the System Administrator of the Linux system being reviewed.

Verify procedures are documented which require the manual scanning of all media used for system maintenance before media is used.

If a procedure is not documented requiring the manual scanning of all media used for system maintenance before media is used, this is a finding.'
  desc 'fix', 'Create procedures, or add to existing system administration procedures, which require the scanning of all media used for system maintenance before media is used.'
  impact 0.5
  ref 'DPMS Target McAfee VSEL Managed Client'
  tag check_id: 'C-63815r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63063'
  tag rid: 'SV-77553r1_rule'
  tag stig_id: 'DTAVSEL-200'
  tag gtitle: 'SRG-APP-000073'
  tag fix_id: 'F-68981r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000870']
  tag nist: ['MA-3 (2)']
end

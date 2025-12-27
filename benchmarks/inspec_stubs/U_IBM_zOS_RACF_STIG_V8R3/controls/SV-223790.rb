control 'SV-223790' do
  title 'IBM z/OS must implement cryptographic mechanisms to prevent unauthorized modification of all information at rest on all operating system components.'
  desc 'Operating systems handling data requiring data at rest protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

'
  desc 'check', "Determine if IBM's DS8880 Disks are in use.

If they are not in use for systems that require data at rest, this is a finding."
  desc 'fix', "Employ IBM's DS8880 hardware to ensure full disk encryption."
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25463r571984_chk'
  tag severity: 'medium'
  tag gid: 'V-223790'
  tag rid: 'SV-223790r604139_rule'
  tag stig_id: 'RACF-OS-000340'
  tag gtitle: 'SRG-OS-000404-GPOS-00183'
  tag fix_id: 'F-25451r515059_fix'
  tag satisfies: ['SRG-OS-000404-GPOS-00183', 'SRG-OS-000405-GPOS-00184']
  tag 'documentable'
  tag legacy: ['SV-107391', 'V-98287']
  tag cci: ['CCI-002475', 'CCI-002476']
  tag nist: ['SC-28 (1)', 'SC-28 (1)']
end

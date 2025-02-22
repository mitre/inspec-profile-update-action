control 'SV-224028' do
  title 'The IBM z/OS systems requiring data at rest protection must properly employ IBM DS8880 for full disk encryption.'
  desc 'Operating systems handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

'
  desc 'check', %q(Determine if IBM's DS880 Disks are in use.

If IBMs DS880 Disks are not in use for systems that require "data at rest", this is a finding.)
  desc 'fix', "Employ IBM's DS8880 hardware to ensure full disk encryption."
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25701r516483_chk'
  tag severity: 'medium'
  tag gid: 'V-224028'
  tag rid: 'SV-224028r561402_rule'
  tag stig_id: 'TSS0-OS-000320'
  tag gtitle: 'SRG-OS-000404-GPOS-00183'
  tag fix_id: 'F-25689r516484_fix'
  tag satisfies: ['SRG-OS-000404-GPOS-00183', 'SRG-OS-000405-GPOS-00184']
  tag 'documentable'
  tag legacy: ['V-98765', 'SV-107869']
  tag cci: ['CCI-002475', 'CCI-002476']
  tag nist: ['SC-28 (1)', 'SC-28 (1)']
end

control 'SV-93699' do
  title 'The IBM z/VM systems requiring data at rest must employ IBMs DS8000 for full disk encryption.'
  desc 'Operating systems handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).'
  desc 'check', %q(Determine if IBM's DS8000 Disks are in use.

If they are not in use for systems that require "data at rest", this is a finding.)
  desc 'fix', "Employ IBM's DS8000 hardware to ensure full disk encryption."
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78581r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78993'
  tag rid: 'SV-93699r1_rule'
  tag stig_id: 'IBMZ-VM-002430'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-85743r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

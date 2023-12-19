control 'SV-251108' do
  title 'The IBM z/OS systems requiring data at rest protection must properly employ IBM DS8880 or equivalent hardware solutions for full disk encryption.'
  desc 'This control addresses the confidentiality and integrity of information at rest and covers user information and system information. Information at rest refers to the state of information when it is located on storage devices as specific components of information systems. Operating systems handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.


'
  desc 'check', %q(Determine if IBM's DS880 Disks or equivalent hardware solutions are in use.

If IBMs DS880 Disks or equivalent hardware solutions  are not in use for systems that require "data at rest", this is a finding.)
  desc 'fix', "Employ IBM's DS8880 hardware or equivalent hardware solutions to ensure full disk encryption."
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-54543r804053_chk'
  tag severity: 'medium'
  tag gid: 'V-251108'
  tag rid: 'SV-251108r877949_rule'
  tag stig_id: 'TSS0-OS-000320'
  tag gtitle: 'SRG-OS-000404-GPOS-00183'
  tag fix_id: 'F-54497r804054_fix'
  tag satisfies: ['SRG-OS-000185-GPOS-00079', 'SRG-OS-000405-GPOS-00184', 'SRG-OS-000404-GPOS-00183', 'SRG-OS-000396-GPOS-00176']
  tag 'documentable'
  tag legacy: ['V-98765', 'SV-107869']
  tag cci: ['CCI-002476', 'CCI-001199', 'CCI-002420', 'CCI-002445', 'CCI-002446']
  tag nist: ['SC-28 (1)', 'SC-28', 'SC-8 (2)', 'SC-12 (2)', 'SC-12 (3)']
end

control 'SV-223788' do
  title 'The IBM z/OS systems requiring data-at-rest protection must properly employ IBM DS8880 or equivalent hardware solutions for full disk encryption.'
  desc 'This control addresses the confidentiality and integrity of information at rest and covers user information and system information. Information at rest refers to the state of information when it is located on storage devices as specific components of information systems. Operating systems handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

'
  desc 'check', "Determine if IBM's DS8880 Disks or equivalent hardware solutions are in use.

If they are not in use for systems that require data at rest, this is a finding."
  desc 'fix', "Employ IBM's DS8880 hardware or equivalent hardware solutions to ensure full disk encryption."
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25461r803636_chk'
  tag severity: 'medium'
  tag gid: 'V-223788'
  tag rid: 'SV-223788r877380_rule'
  tag stig_id: 'RACF-OS-000320'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-25449r803664_fix'
  tag satisfies: ['SRG-OS-000185-GPOS-00079', 'SRG-OS-000405-GPOS-00184', 'SRG-OS-000404-GPOS-00183', 'SRG-OS-000396-GPOS-00176']
  tag 'documentable'
  tag legacy: ['SV-107387', 'V-98283']
  tag cci: ['CCI-001199', 'CCI-002420', 'CCI-002445', 'CCI-002446']
  tag nist: ['SC-28', 'SC-8 (2)', 'SC-12 (2)', 'SC-12 (3)']
end

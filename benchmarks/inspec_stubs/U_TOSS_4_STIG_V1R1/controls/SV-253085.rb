control 'SV-253085' do
  title 'All TOSS local disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.'
  desc 'TOSS systems handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

'
  desc 'check', 'Verify TOSS prevents unauthorized disclosure or modification of all information requiring at-rest protection by using disk encryption. 

If there is a documented and approved reason for not having data-at-rest encryption, this requirement is Not Applicable.

Verify all local system partitions are encrypted with the following command:

$ sudo blkid

/dev/mapper/rhel-root: UUID="67b7d7fe-de60-6fd0-befb-e6748cf97743" TYPE="crypto_LUKS"

Every persistent disk partition present must be of TYPE "crypto_LUKS." If any partitions other than pseudo file systems (such as /proc or /sys) are not type "crypto_LUKS", ask the administrator to indicate how the partitions are encrypted. If there is no evidence that all local disk partitions are encrypted, this is a finding.'
  desc 'fix', 'Configure TOSS to prevent unauthorized modification of all information at rest by using disk encryption. 

Encrypting a partition in an already installed system is more difficult, because existing partitions will need to be resized and changed. To encrypt an entire partition, dedicate a partition for encryption in the partition layout.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56538r824925_chk'
  tag severity: 'medium'
  tag gid: 'V-253085'
  tag rid: 'SV-253085r824927_rule'
  tag stig_id: 'TOSS-04-040330'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-56488r824926_fix'
  tag satisfies: ['SRG-OS-000185-GPOS-00079', 'SRG-OS-000404-GPOS-00183', 'SRG-OS-000405-GPOS-00184']
  tag 'documentable'
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)', 'SC-28 (1)']
end

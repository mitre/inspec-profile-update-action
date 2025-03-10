control 'SV-248525' do
  title 'All OL 8 local disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at-rest protection.'
  desc 'OL 8 systems handling data requiring "data-at-rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. 
 
Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).

'
  desc 'check', 'Verify OL 8 prevents unauthorized disclosure or modification of all information requiring at rest protection by using disk encryption. 
 
If there is a documented and approved reason for not having data-at-rest encryption, this requirement is not applicable. 
  
Verify all system partitions are encrypted with the following command: 
 
$ sudo blkid

/dev/mapper/ol-root:  UUID="67b7d7fe-de60-6fd0-befb-e6748cf97743" TYPE="crypto_LUKS"
 
Every persistent disk partition present must be of type "crypto_LUKS".
 
If any partitions other than the boot partition or pseudo file systems (such as "/proc" or "/sys") are not listed, ask the administrator to indicate how the partitions are encrypted.  If there is no evidence that these partitions are encrypted, this is a finding.'
  desc 'fix', 'Configure OL 8 to prevent unauthorized modification of all information at rest by using disk encryption. 
 
Encrypting a partition in an already-installed system is more difficult because existing partitions will need to be resized and changed.  
 
To encrypt an entire partition, dedicate a partition for encryption in the partition layout.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51959r818595_chk'
  tag severity: 'medium'
  tag gid: 'V-248525'
  tag rid: 'SV-248525r818596_rule'
  tag stig_id: 'OL08-00-010030'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-51913r779140_fix'
  tag satisfies: ['SRG-OS-000185-GPOS-00079', 'SRG-OS-000404-GPOS-00183', 'SRG-OS-000405-GPOS-00184']
  tag 'documentable'
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)', 'SC-28 (1)']
end

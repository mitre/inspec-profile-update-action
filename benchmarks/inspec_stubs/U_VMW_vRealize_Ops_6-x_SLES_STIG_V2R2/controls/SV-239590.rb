control 'SV-239590' do
  title 'The SLES for vRealize must use cryptographic mechanisms to protect the integrity of audit tools.'
  desc 'Protecting the integrity of the tools used for auditing purposes is a critical step toward ensuring the integrity of audit information. Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

It is not uncommon for attackers to replace the audit tools or inject code into the existing tools with the purpose of providing the capability to hide or erase system activity from the audit logs.

To address this risk, audit tools must be cryptographically signed in order to provide the capability to identify when the audit tools have been modified, manipulated, or replaced. An example is a checksum hash of the file or files.'
  desc 'check', %q(The following command will list which audit files on the system have file hashes different from what is expected by the RPM database:

# rpm -V audit | grep '$1 ~ /..5/ && $2 != "c"'

If there is output, this is a finding.)
  desc 'fix', %q(The RPM package management system can check the hashes of audit system package files. Run the following command to list which audit files on the system have hashes that differ from what is expected by the RPM database: 

# rpm -V audit | grep '^..5'

A "c" in the second column indicates that a file is a configuration file, which may appropriately be expected to change. If the file that has changed was not expected to, refresh from distribution media or online repositories. 

rpm -Uvh [affected_package])
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42823r662219_chk'
  tag severity: 'medium'
  tag gid: 'V-239590'
  tag rid: 'SV-239590r877393_rule'
  tag stig_id: 'VROM-SL-000930'
  tag gtitle: 'SRG-OS-000278-GPOS-00108'
  tag fix_id: 'F-42782r662220_fix'
  tag 'documentable'
  tag legacy: ['SV-99301', 'V-88651']
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
end

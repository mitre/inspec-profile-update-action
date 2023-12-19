control 'SV-93567' do
  title 'CA VM:Secure product AUDIT file must be restricted to authorized personnel.'
  desc 'Unauthorized disclosure of audit records can reveal system and configuration data to attackers, thus compromising its confidentiality.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit operating system activity.

'
  desc 'check', 'Determine the VMSECURE Audit disk.
Note: Consult the z/VM system administrator for this information.

Review all rules that grant access to the identified VM:Secure AUDIT disk.

If any grant access to anyone other than a system administrator or security administrator, this is a finding.'
  desc 'fix', 'Ensure access to VMSECURE AUDIT disk is restricted to system administrators or security administrators.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78447r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78861'
  tag rid: 'SV-93567r1_rule'
  tag stig_id: 'IBMZ-VM-000190'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-85611r1_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end

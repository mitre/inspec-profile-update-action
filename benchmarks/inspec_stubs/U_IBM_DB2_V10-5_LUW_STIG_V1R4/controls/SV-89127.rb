control 'SV-89127' do
  title 'The audit information produced by DB2 must be protected from unauthorized read access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from any and all unauthorized access. This includes read, write, copy, etc.

This requirement can be achieved through multiple methods which will depend upon system architecture and design. Some commonly employed methods include ensuring log files enjoy the proper file system permissions utilizing file system protections and limiting log data location. 

Additionally, applications with user interfaces to audit records should not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring that audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.'
  desc 'check', 'Run db2audit command to find the value of datapath where the audit logs are stored. 

     $db2audit describe

Only the instance owner needs write access to directory and users authorized to archive the audit logs need to have read access to audit directory. 

If any user other than the instance owner has write access to audit directory, this is a finding.

If any user other than the users authorized to read audit log files have read access to audit directory, this is a finding.'
  desc 'fix', 'Remove the write permission from non-instance owner users on the audit directory.

Remove the read permission from non-authorized users from audit directory.

Only the instance owner needs write access to directory and users authorized to archive the audit logs need to have read access to audit directory. 

Change the permissions on audit datapath and archivepath directories so that only the instance owner has write access on datapath and users with audit archive privileges have read access on datapath. Only users with SYSADM and SECADM privileges and can extract and archive the audit logs.'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74379r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74453'
  tag rid: 'SV-89127r1_rule'
  tag stig_id: 'DB2X-00-002200'
  tag gtitle: 'SRG-APP-000118-DB-000059'
  tag fix_id: 'F-81053r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end

control 'SV-223458' do
  title 'CA-ACF2 must limit Update and Allocate access to system backup files to system programmers and/or batch jobs that perform DASD backups.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'Collect from the storage management group the identification of the DASD backup files and all associated storage management userids/LIDs/ACIDs.

If ESM data set rules for system DASD backup files do not restrict UPDATE and ALLOCATE access to z/OS systems programming and/or batch jobs that perform DASD backups, this is a finding.

If  READ Access to system backup data sets is not limited to auditors and others approved by the ISSM, this is a finding.'
  desc 'fix', "Obtain the high level indexes to backup data sets names define their access to be restricted by the System's ESM to System Programmers and batch jobs that perform the backups. Define READ Access to system backup data sets to be limited to auditors and others approved by the ISSM."
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25131r504501_chk'
  tag severity: 'medium'
  tag gid: 'V-223458'
  tag rid: 'SV-223458r533198_rule'
  tag stig_id: 'ACF2-ES-000380'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-25119r504502_fix'
  tag 'documentable'
  tag legacy: ['V-97613', 'SV-106717']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end

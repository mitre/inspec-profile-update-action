control 'SV-237433' do
  title 'SCOM unsealed management packs must be backed up regularly.'
  desc "SCOM's configuration information is stored within unsealed management packs. Even without SQL backups, a catastrophic failure to SCOM can be recovered from quickly if the unsealed management packs have been backed up.

"
  desc 'check', "There is more than one way to configure this, and it will be at an administrator's discretion. 

Open task scheduler and check for the presence of a scheduled task to back up unsealed management packs. If present, review the script to determine where backups are being stored. 

Verify that the unsealed management packs are being saved to the location specified in the task and that the location is being backed up regularly. 

Alternatively, several free management packs do exist to automate this process within SCOM, or an administrator could automate this with their own custom management pack or using an orchestration tool such as System Center Orchestrator. 

This is not a finding if an administrator can show that one of these is installed/configured and that unsealed management packs are being written to the configured location.

If unsealed management packs are not being exported to disk and backed up, this is a finding."
  desc 'fix', 'The quickest solution available is to download the management pack referenced in this article and configure it accordingly: https://kevinholman.com/2017/07/07/scom-2012-and-2016-unsealed-mp-backup/

Ultimately, this is an organizational decision as to how the administrator would like to proceed.'
  impact 0.3
  ref 'DPMS Target Microsoft SCOM'
  tag check_id: 'C-40652r643943_chk'
  tag severity: 'low'
  tag gid: 'V-237433'
  tag rid: 'SV-237433r643945_rule'
  tag stig_id: 'SCOM-CM-000002'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-40615r643944_fix'
  tag satisfies: ['SRG-APP-000516-NDM-000340', 'SRG-APP-000516-NDM-000341']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000537', 'CCI-000539']
  tag nist: ['CM-6 b', 'CP-9 (b)', 'CP-9 (c)']
end

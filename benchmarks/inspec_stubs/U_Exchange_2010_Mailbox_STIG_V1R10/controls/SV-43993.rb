control 'SV-43993' do
  title 'Public Store storage quota must be limited.'
  desc 'This setting controls the maximum sizes of a Public Folder and the system’s response if these limits are exceeded. There are two available controls and the system response when the quota has been exceeded. 

The first control sends an email warning to Folder Owners roles alerting them that the folder has exceeded its quota.  The second level prevents posting any additional items to the folder.  

As a practical matter, level 1 serves the purpose of prompting owners to manage their folders.  Level 2 impedes users in their ability to work, and is not required where folder use interruption is not acceptable.   Public Folder Storage Quota Limitations are not a substitute for overall disk space monitoring.'
  desc 'check', "If public folders are not used this check is NA.

Obtain the Email Domain Security Plan (EDSP)  and locate the value for 'ProhibitPostQuota'.

Open the Exchange Management Shell and enter the following command:

Get-PublicFolderDatabase | Select Name, Identity, ProhibitPostQuota

If the value of 'ProhibitPostQuota' is not set to the sites 'ProhibitPostQuota', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command: 

Set-PublicFolderDatabase <'publicdatabasename'> -ProhibitPostQuota <'SitesProhibitPostQuotaLimit'>"
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41679r1_chk'
  tag severity: 'low'
  tag gid: 'V-33573'
  tag rid: 'SV-43993r1_rule'
  tag stig_id: 'Exch-1-106'
  tag gtitle: 'Exch-1-106'
  tag fix_id: 'F-37464r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end

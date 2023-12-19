control 'SV-239886' do
  title 'The Cisco ASA must be configured to block malicious code.'
  desc 'Configuring the IDPS to delete and/or quarantine based on local organizational incident handling procedures minimizes the impact of this code on the network.'
  desc 'check', 'Verify that a file policy is applied to an access control policy.

Step 1: Navigate to  Configuration >> ASA FirePOWER Configuration >> Policies >> Access Control Policy. The Access Control Policy page appears.

Step 2: Click the edit icon next to the access control policy enabled for AMP or file control.

Step 3: Click the edit icon next to the rule you want to edit. The access control rule editor appears.

Step 4: Verify that the rule action is Interactive Block or Interactive Block with reset.

Step 5: Select the Inspection tab. The Inspection tab appears.

Step 6: Verify that a file policy has been selected to inspect traffic.
-------------------------------------------------
Verify that the file policy blocks malware.

Step 1: Select Configuration >> ASA FirePOWER Configuration >> Policies >> Files. The File Policies page appears.

Step 2: Click the edit icon next to the file policy for malware. The File Policy Rules tab appears.

Step 3: Verify that application protocols have been selected or any.

Note: Any detects files in HTTP, SMTP, IMAP, POP3, FTP, and NetBIOS-ssn (SMB) traffic.

Step 4: Verify that the rule action is Block Malware.

If the ASA is not configured to block malicious code, this is a finding.'
  desc 'fix', 'Create a file policy.

Step 1: Navigate to Configuration >> ASA FirePOWER Configuration >> Policies >> Files. The File Policies page appears.

Step 2: Enter a Name and optional Description for your new policy, then click Save. The File Policy Rules tab appears.

Step 3: Click Add File Rule. The Add File Rule dialog box appears.

Step 4: Select an Application Protocol from the drop-down list. 

Note: Any detects files in HTTP, SMTP, IMAP, POP3, FTP, and NetBIOS-ssn (SMB) traffic.

Step 5: Select rule action Block Malware.

Step 6: Select one or more File Types.

Step 7: Add the selected file types (e.g., multimedia, executables, etc.) to the Selected Files Categories and Types list by clicking Add to add selected file types to the rule. Drag and drop one or more file types into the Selected Files Categories and Types list.

Step 8: Click Store ASA FirePOWER Changes.
---------------------------------------------------------------
Apply the file policy to an access control policy.

Step 1: Navigate to Configuration >> ASA FirePOWER Configuration >> Policies > Access Control Policy. The Access Control Policy page appears.

Step 2: Click the edit icon next to the access control policy where you want to configure AMP or file control using access control rules.

Step 3: Create or the edit icon next to the rule you want to edit. The access control rule editor appears.

Step 4: Set the rule action Interactive Block or Interactive Block with reset.

Step 5: Select the Inspection tab. The Inspection tab appears.

Step 6: Select the configured file policy to inspect traffic.

Step 7: Click Add to save the rule.'
  impact 0.5
  ref 'DPMS Target Cisco ASA IPS'
  tag check_id: 'C-43119r665969_chk'
  tag severity: 'medium'
  tag gid: 'V-239886'
  tag rid: 'SV-239886r665971_rule'
  tag stig_id: 'CASA-IP-000260'
  tag gtitle: 'SRG-NET-000249-IDPS-00176'
  tag fix_id: 'F-43078r665970_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end

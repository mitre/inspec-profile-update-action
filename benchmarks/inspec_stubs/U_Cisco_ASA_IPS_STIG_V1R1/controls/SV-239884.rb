control 'SV-239884' do
  title 'The Cisco ASA must block any prohibited mobile code at the enclave boundary when it is detected.'
  desc "Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient. Examples of mobile code include JavaScript, VBScript, Java applets, ActiveX controls, Flash animations, Shockwave videos, and macros embedded within Microsoft Office documents. Mobile code can be exploited to attack a host. It can be sent as an e-mail attachment or embedded in other file formats not traditionally associated with executable code. 

While the IDPS cannot replace the anti-virus and host-based IDS (HIDS) protection installed on the network's endpoints, vendor or locally created sensor rules can be implemented, which provide preemptive defense against both known and zero-day vulnerabilities. Many of the protections may provide defenses before vulnerabilities are discovered and rules or blacklist updates are distributed by anti-virus or malicious code solution vendors.

To block known prohibited mobile code or approved mobile code that violates permitted usage requirements, the IDPS must implement policy filters, rules, signatures, and anomaly analysis."
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

If the ASA is not configured to block any prohibited mobile code at the enclave boundary, this is a finding.'
  desc 'fix', 'Create a file policy.

Step 1: Select Configuration >> ASA FirePOWER Configuration> > Policies >> Files. The File Policies page appears.

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

Step 1: Navigate to  Configuration >> ASA FirePOWER Configuration >> Policies >> Access Control Policy. The Access Control Policy page appears.

Step 2: Click the edit icon next to the access control policy where you want to configure AMP or file control using access control rules.

Step 3: Create or the edit icon next to the rule you want to edit. The access control rule editor appears.

Step 4: Set the rule action Interactive Block or Interactive Block with reset.

Step 5: Select the Inspection tab. The Inspection tab appears.

Step 6: Select the configured file policy to inspect traffic.

Step 7: Click Add to save the rule.'
  impact 0.5
  ref 'DPMS Target Cisco ASA IPS'
  tag check_id: 'C-43117r665963_chk'
  tag severity: 'medium'
  tag gid: 'V-239884'
  tag rid: 'SV-239884r665965_rule'
  tag stig_id: 'CASA-IP-000200'
  tag gtitle: 'SRG-NET-000229-IDPS-00163'
  tag fix_id: 'F-43076r665964_fix'
  tag 'documentable'
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end

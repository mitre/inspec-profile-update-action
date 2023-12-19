control 'SV-94973' do
  title 'Samsung Android 8 with Knox must implement the management setting: CONTAINER Account blacklist.'
  desc 'Blacklisting all email accounts is required so only whitelisted accounts can be configured.

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Review Samsung Android 8 with Knox configuration settings to determine if the mobile device is enforcing CONTAINER Account Blacklisting. 

This validation procedure is performed on both the MDM Administration Console and the Samsung Android 8 with Knox device.

On the MDM console, do the following:
1. Ask the MDM Administrator to display the "Account blacklist" setting in the "CONTAINER Accounts" rule. 
2. Verify the setting is configured to all email domains not approved by DoD.
Note: All email domains are specified by the wildcard string ".*"

On the Samsung Android 8 with Knox device, do the following:
1. Open the Knox CONTAINER.
2. Open "Workspace settings".
3. Select "Accounts".
4. Select "Add account".
5. Select "Email" (and repeat for Microsoft Exchange ActiveSync) and attempt to add an email account with a non-approved domain.
6. Verify the email account cannot be added.

If the MDM console "Account blacklist" is not set to all email domains not approved by DoD or on the Samsung Android 8 with Knox device, the user is able to successfully configure the non-DoD-approved email account, this is a finding.'
  desc 'fix', 'Configure Samsung Android 8 with Knox to enforce CONTAINER Account Blacklisting.

On the MDM console, add all email domains not approved by DoD to the "Account blacklist" setting in the "CONTAINER Accounts" rule or blacklist all accounts by using the wildcard string ".*" The wildcard string will blacklist all email accounts except for those on the whitelist.'
  impact 0.5
  ref 'DPMS Target Samsung Android OS 8 with Knox 3.x - COPE use case'
  tag check_id: 'C-79941r3_chk'
  tag severity: 'medium'
  tag gid: 'V-80269'
  tag rid: 'SV-94973r1_rule'
  tag stig_id: 'KNOX-08-000400'
  tag gtitle: 'PP-MDF-991000'
  tag fix_id: 'F-87075r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

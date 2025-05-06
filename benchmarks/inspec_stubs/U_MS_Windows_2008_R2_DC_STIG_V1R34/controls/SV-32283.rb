control 'SV-32283' do
  title 'Anonymous enumeration of shares will be restricted.'
  desc 'This is a Category 1 finding because it allows anonymous logon users (null session connections) to list all account names and enumerate all shared resources, thus providing a map of potential points to attack the system.

By default, Windows allows anonymous users to list account names and enumerate share names.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for “Network access: Do not allow anonymous enumeration of SAM accounts and shares” is not set to “Enabled”, then this is a finding. 

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Lsa\\

Value Name:  RestrictAnonymous

Value Type:  REG_DWORD
Value:  1

Documentable Explanation: If the required settings cannot be used to allow for proper operation in a mixed Windows environment, then this should be documented with the IAO.'
  desc 'fix', 'Configure the policy values for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Do not allow anonymous enumeration of SAM accounts and shares” to “Enabled".'
  impact 0.7
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-33804r1_chk'
  tag severity: 'high'
  tag gid: 'V-1093'
  tag rid: 'SV-32283r1_rule'
  tag gtitle: 'Anonymous shares are not restricted'
  tag fix_id: 'F-29449r1_fix'
  tag potential_impacts: 'In a mixed Windows environment, this setting may cause systems with down-level operating systems to fail to authenticate, may prevent their users from changing their passwords, and may cause problems with managing printers and spools.

In domains supporting Exchange 2003 servers and versions of Outlook earlier than Outlook 2003, the setting “Network access: Do not allow anonymous enumeration of SAM accounts and shares” should be set to “Disabled” on the Domain Controller Group Policy to allow Outlook to anonymously query the global catalog service.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end

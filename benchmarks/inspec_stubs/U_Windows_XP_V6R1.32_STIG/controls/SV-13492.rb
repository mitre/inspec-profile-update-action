control 'SV-13492' do
  title 'Anonymous access to the Registry is not restricted.'
  desc 'This is a Category I finding, because this vulnerability allows an anonymous individual read-access and write-access to some parts of the Registry. 

The permissions set for the Winreg subkey determine who can remotely connect to a registry.  If this subkey does not exist, all users can remotely connect to the registry.  To remotely connect to a registry, a user must have at least Read Access to the Winreg subkey on the target computer.

The Everyone group, which is given permissions by the default installation, typically has at least enough access allowed to browse.   Therefore, the capability for an anonymous user to access the Registry over the network must be prevented.'
  desc 'check', 'Wiindows XP/2003/Vista/2008 - Using the Registry Editor, navigate to the following Key: MACHINE/System/CurrentControlSet/Control/SecurePipeServers/Winreg If the key does not exist, then this is a finding. If the permissions are not at least as restrictive as those below, then this is a finding. Administrators all Backup Operators read(QENR) Local Service read (Exchange Enterprise Servers group on Domain Controllers and Exchange server all
 
 
Documentable Explanation: On DCs and Exchange Servers, if permissions are sub-delegated with the Exchange Management console, then additional accounts and groups may appear on the Winreg key. If this has been done then these should be documented with the site IAO and made available for any reviewer.'
  desc 'fix', 'Configure the system to prevent anonymous users from gaining access to the Registry.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-9577r1_chk'
  tag severity: 'high'
  tag gid: 'V-1152'
  tag rid: 'SV-13492r1_rule'
  tag gtitle: 'Anonymous Access to the Registry'
  tag fix_id: 'F-90r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECCD-1, ECCD-2'
end

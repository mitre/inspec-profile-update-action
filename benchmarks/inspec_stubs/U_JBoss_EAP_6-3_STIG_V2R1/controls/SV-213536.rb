control 'SV-213536' do
  title 'JBoss file permissions must be configured to protect the confidentiality and integrity of application files.'
  desc 'The JBoss EAP Application Server is a Java-based AS.  It is installed on the OS file system and depends upon file system access controls to protect application data at rest.  The file permissions set on the JBoss EAP home folder must be configured so as to limit access to only authorized people and processes.  The account used for operating the JBoss server and any designated administrative or operational accounts are the only accounts that should have access.

When data is written to digital media such as hard drives, mobile computers, external/removable hard drives, personal digital assistants, flash/thumb drives, etc., there is risk of data loss and data compromise.  Steps must be taken to ensure data stored on the device is protected.'
  desc 'check', 'By default, JBoss installs its files into a folder called "jboss-eap-6.3".   This folder by default is stored within the home folder of the JBoss user account.  The installation process, however, allows for the override of default values to obtain folder and user account information from the system admin.

Log on with a user account with JBoss access and permissions. 

Navigate to the "Jboss-eap-6.3" folder using the relevant OS commands for either a UNIX-like OS or a Windows OS.

Examine the permissions of the JBoss folder.

Owner can be full access.
Group can be full access.
All others must be restricted to execute access or no permission.

If the JBoss folder is world readable or world writeable, this is a finding.'
  desc 'fix', 'Configure file permissions on the JBoss folder to protect from unauthorized access.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14759r296274_chk'
  tag severity: 'medium'
  tag gid: 'V-213536'
  tag rid: 'SV-213536r615939_rule'
  tag stig_id: 'JBOS-AS-000400'
  tag gtitle: 'SRG-APP-000231-AS-000133'
  tag fix_id: 'F-14757r296275_fix'
  tag 'documentable'
  tag legacy: ['SV-76789', 'V-62299']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end

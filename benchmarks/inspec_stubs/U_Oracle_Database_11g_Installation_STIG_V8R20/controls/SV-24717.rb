control 'SV-24717' do
  title 'The DBMS should not share a host supporting an independent security service.'
  desc 'The Security Support Structure is a security control function or service provided by an external system or application. An example of this would be a Windows domain controller that provides identification and authentication that can be used by other systems to control access. The associated risk of a DBMS installed on a system that provides security support is significantly higher than when installed on separate systems. In cases where the DBMS is dedicated to local support of a security support function (e.g. a directory service), separation may not be possible.'
  desc 'check', 'Review the services and processes active on the DBMS host system.
 
If the host system is a Windows domain controller, this is a Finding.

If the host system is supporting any other security or directory services that do not use the DBMS to store information, this is a Finding.

NOTE: This does not include client security applications like firewall and antivirus software.'
  desc 'fix', 'Either move the DBMS installation to a dedicated host system or move the directory or security services to another host system.

A dedicated host system in this case refers to an instance of the operating system at a minimum.

The operating system may reside on a virtual host machine where supported by the DBMS vendor.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29351r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15179'
  tag rid: 'SV-24717r1_rule'
  tag stig_id: 'DG0110-ORACLE11'
  tag gtitle: 'DBMS host shared with a security service'
  tag fix_id: 'F-26376r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end

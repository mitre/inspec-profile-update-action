control 'SV-213604' do
  title 'The EDB Postgres Advanced Server must protect the confidentiality and integrity of all information at rest.'
  desc 'This control is intended to address the confidentiality and integrity of information at rest in non-mobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system. Applications and application users generate information throughout the course of their application use. 

User data generated, as well as application-specific configuration data, needs to be protected. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate. 

If the confidentiality and integrity of application data is not protected, the data will be open to compromise and unauthorized modification.'
  desc 'check', 'If the application owner and Authorizing Official have determined that encryption of data at rest is NOT required, this is not a finding.

Execute the following command as root:

> df

If the mounted  filesystem where "<postgresql data directory>" exists is not located on an encrypted disk partition, this is a finding.  

(The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)'
  desc 'fix', 'Create an encrypted partition to host the "<postgresql data directory>" directory. This can be done at the OS level with a technology such as db-crypt or other encryption technologies provided by third-party tools. 

One option is to use LUKS as documented here: https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Security_Guide/sec-Encryption.html

(The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)'
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14826r290124_chk'
  tag severity: 'high'
  tag gid: 'V-213604'
  tag rid: 'SV-213604r836844_rule'
  tag stig_id: 'PPS9-00-005700'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-14824r290125_fix'
  tag 'documentable'
  tag legacy: ['SV-83565', 'V-68961']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end

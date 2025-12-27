control 'SV-248685' do
  title 'OL 8 must map the authenticated identity to the user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis. 
 
There are various methods of mapping certificates to user/group accounts for OL 8. For the purposes of this requirement, the check and fix will account for Active Directory mapping. Some of the other possible methods include joining the system to a domain and using an idM server, or a local system mapping, where the system is not part of a domain.'
  desc 'check', 'Verify the certificate of the user or group is mapped to the corresponding user or group in the "sssd.conf" file with the following command:

Note: If the System Administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

$ sudo cat /etc/sssd/sssd.conf

[sssd]
config_file_version = 2
services = pam, sudo, ssh
domains = testing.test

[pam]
pam_cert_auth = True

[domain/testing.test]
id_provider = ldap

[certmap/testing.test/rule_name]
matchrule =<SAN>.*EDIPI@mil
maprule = (userCertificate;binary={cert!bin})
domains = testing.test

If the "certmap" section does not exist, this is a finding.'
  desc 'fix', 'Configure OL 8 to map the authenticated identity to the user or group account by adding or modifying the "certmap" section of the "/etc/sssd/sssd.conf" file based on the following example: 
 
[certmap/testing.test/rule_name] 
matchrule =<SAN>.*EDIPI@mil 
maprule = (userCertificate;binary={cert!bin}) 
domains = testing.test 
 
The "sssd" service must be restarted for the changes to take effect. To restart the "sssd" service, run the following command: 
 
$ sudo systemctl restart sssd.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52119r858605_chk'
  tag severity: 'medium'
  tag gid: 'V-248685'
  tag rid: 'SV-248685r858606_rule'
  tag stig_id: 'OL08-00-020090'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag fix_id: 'F-52073r779620_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end

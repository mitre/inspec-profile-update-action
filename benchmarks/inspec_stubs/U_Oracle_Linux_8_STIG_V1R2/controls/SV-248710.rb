control 'SV-248710' do
  title 'OL 8 must prohibit the use of cached authentications after one day.'
  desc 'If cached authentication information is out of date, the validity of the authentication information may be questionable. 
 
OL 8 includes multiple options for configuring authentication, but this requirement will focus on the System Security Services Daemon (SSSD). By default, SSSD does not cache credentials.'
  desc 'check', 'Verify that the SSSD prohibits the use of cached authentications after one day. 
 
Note: If smart card authentication is not being used on the system, this item is not applicable. 
 
Check that SSSD allows cached authentications with the following command: 
 
$ sudo grep cache_credentials /etc/sssd/sssd.conf 
 
cache_credentials = true 
 
If "cache_credentials" is set to "false" or is missing from the configuration file, this is not a finding and no further checks are required. 
 
If "cache_credentials" is set to "true", check that SSSD prohibits the use of cached authentications after one day with the following command: 
 
$ sudo grep offline_credentials_expiration  /etc/sssd/sssd.conf 
 
offline_credentials_expiration = 1 
 
If "offline_credentials_expiration" is not set to a value of "1", this is a finding.'
  desc 'fix', 'Configure the SSSD to prohibit the use of cached authentications after one day. 
 
Add or change the following line in "/etc/sssd/sssd.conf" just below the line "[pam]". 
 
offline_credentials_expiration = 1'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52144r779694_chk'
  tag severity: 'medium'
  tag gid: 'V-248710'
  tag rid: 'SV-248710r779696_rule'
  tag stig_id: 'OL08-00-020290'
  tag gtitle: 'SRG-OS-000383-GPOS-00166'
  tag fix_id: 'F-52098r779695_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end

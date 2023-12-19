control 'SV-252933' do
  title 'TOSS must prohibit the use of cached authentications after one day.'
  desc 'If cached authentication information is out of date, the validity of the authentication information may be questionable.

TOSS includes multiple options for configuring authentication, but this requirement will be focus on the System Security Services Daemon (SSSD). By default, sssd does not cache credentials.'
  desc 'check', 'Verify that SSSD prohibits the use of cached authentications after one day.

Note: If smart card authentication is not being used on the system, this item is Not Applicable.

Check that SSSD allows cached authentications with the following command:

$ sudo grep cache_credentials /etc/sssd/sssd.conf

cache_credentials = true

If "cache_credentials" is set to "false" or missing from the configuration file, this is not a finding and no further checks are required.

If "cache_credentials" is set to "true", check that SSSD prohibits the use of cached authentications after one day with the following command:

$ sudo grep offline_credentials_expiration /etc/sssd/sssd.conf

offline_credentials_expiration = 1

If "offline_credentials_expiration" is not set to a value of "1", this is a finding.'
  desc 'fix', 'Configure the SSSD to prohibit the use of cached authentications after one day.

Add or change the following line in "/etc/sssd/sssd.conf" just below the line "[pam]."

offline_credentials_expiration = 1'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56386r824121_chk'
  tag severity: 'medium'
  tag gid: 'V-252933'
  tag rid: 'SV-252933r824123_rule'
  tag stig_id: 'TOSS-04-010250'
  tag gtitle: 'SRG-OS-000383-GPOS-00166'
  tag fix_id: 'F-56336r824122_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end

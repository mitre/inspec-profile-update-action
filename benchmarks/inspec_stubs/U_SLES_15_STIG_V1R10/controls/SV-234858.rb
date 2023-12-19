control 'SV-234858' do
  title 'The SUSE operating system must configure the Linux Pluggable Authentication Modules (PAM) to prohibit the use of cached offline authentications after one day.'
  desc 'If cached authentication information is out of date, the validity of the authentication information may be questionable.'
  desc 'check', 'If SSSD is not being used on the operating system, this is Not Applicable.

Verify that the SUSE operating system PAM prohibits the use of cached off line authentications after one day.

Check that cached off line authentications cannot be used after one day with the following command:

> sudo grep "offline_credentials_expiration" /etc/sssd/sssd.conf

offline_credentials_expiration = 1

If "offline_credentials_expiration" is not set to a value of "1", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system PAM to prohibit the use of cached authentications after one day. 

Add or change the following line in "/etc/sssd/sssd.conf" just below the line "[pam]":

offline_credentials_expiration = 1'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38046r618843_chk'
  tag severity: 'medium'
  tag gid: 'V-234858'
  tag rid: 'SV-234858r854204_rule'
  tag stig_id: 'SLES-15-010500'
  tag gtitle: 'SRG-OS-000383-GPOS-00166'
  tag fix_id: 'F-38009r618844_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end

control 'SV-217167' do
  title 'The SUSE operating system must configure the Linux Pluggable Authentication Modules (PAM) to prohibit the use of cached offline authentications after one day.'
  desc 'If cached authentication information is out of date, the validity of the authentication information may be questionable.'
  desc 'check', 'If SSSD is not being used on the operating system, this is Not Applicable.

Verify that the SUSE operating system Pluggable Authentication Modules (PAM) prohibits the use of cached off line authentications after one day.

Check that cached off line authentications cannot be used after one day with the following command:

# sudo grep "offline_credentials_expiration" /etc/sssd/sssd.conf

offline_credentials_expiration = 1

If "offline_credentials_expiration" is not set to a value of "1", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system PAM to prohibit the use of cached authentications after one day. 

Add or change the following line in "/etc/sssd/sssd.conf" just below the line "[pam]":

offline_credentials_expiration = 1'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18395r369657_chk'
  tag severity: 'medium'
  tag gid: 'V-217167'
  tag rid: 'SV-217167r854095_rule'
  tag stig_id: 'SLES-12-010680'
  tag gtitle: 'SRG-OS-000383-GPOS-00166'
  tag fix_id: 'F-18393r369658_fix'
  tag 'documentable'
  tag legacy: ['V-77185', 'SV-91881']
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end

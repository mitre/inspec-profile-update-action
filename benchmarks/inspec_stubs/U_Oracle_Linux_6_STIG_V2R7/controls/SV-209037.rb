control 'SV-209037' do
  title 'The operating system must manage information system identifiers for users and devices by disabling the user identifier after an organization defined time period of inactivity.'
  desc 'Disabling inactive accounts ensures that accounts which may not have been responsibly removed are not available to attackers who may have compromised their credentials.'
  desc 'check', 'To verify the "INACTIVE" setting, run the following command: 

grep "INACTIVE" /etc/default/useradd

The output should indicate the "INACTIVE" configuration option is set to an appropriate integer as shown in the example below: 

# grep "INACTIVE" /etc/default/useradd
INACTIVE=35

If it does not, this is a finding.'
  desc 'fix', 'To specify the number of days after a password expires (which signifies inactivity) until an account is permanently disabled, add or correct the following lines in "/etc/default/useradd", substituting "[NUM_DAYS]" appropriately: 

INACTIVE=[NUM_DAYS]

A value of 35 is recommended. If a password is currently on the verge of expiration, then 35 days remain until the account is automatically disabled. However, if the password will not expire for another 60 days, then 95 days could elapse until the account would be automatically disabled.

See the "useradd" man page for more information.

Determining the inactivity timeout must be done with careful consideration of the length of a "normal" period of inactivity for users in the particular environment.

Setting the timeout too low incurs support costs and also has the potential to impact availability of the system to legitimate users.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9290r357896_chk'
  tag severity: 'low'
  tag gid: 'V-209037'
  tag rid: 'SV-209037r793758_rule'
  tag stig_id: 'OL6-00-000335'
  tag gtitle: 'SRG-OS-000118'
  tag fix_id: 'F-9290r357897_fix'
  tag 'documentable'
  tag legacy: ['SV-65341', 'V-51131']
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end

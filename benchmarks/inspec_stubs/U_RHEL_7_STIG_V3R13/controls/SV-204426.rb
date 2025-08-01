control 'SV-204426' do
  title 'The Red Hat Enterprise Linux operating system must disable account identifiers (individuals, groups, roles, and devices) if the password expires.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

Operating systems need to track periods of inactivity and disable application identifiers after 35 days of inactivity.'
  desc 'check', 'If passwords are not being used for authentication, this is Not Applicable.

Verify the operating system disables account identifiers (individuals, groups, roles, and devices) after the password has expired with the following command:

     # grep -i inactive /etc/default/useradd
     INACTIVE=35

If "INACTIVE" is set to "-1", a value greater than "35", is commented out, or is not defined, this is a finding.'
  desc 'fix', 'Configure the operating system to disable account identifiers (individuals, groups, roles, and devices) 35 days after the password has expired.

Add the following line to "/etc/default/useradd" (or modify the line to have the required value):

     INACTIVE=35

DOD recommendation is 35 days, but a lower value is acceptable. The value "-1" will disable this feature, and "0" will disable the account immediately after the password expires.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4550r928566_chk'
  tag severity: 'medium'
  tag gid: 'V-204426'
  tag rid: 'SV-204426r928568_rule'
  tag stig_id: 'RHEL-07-010310'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-4550r928567_fix'
  tag 'documentable'
  tag legacy: ['SV-86565', 'V-71941']
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end

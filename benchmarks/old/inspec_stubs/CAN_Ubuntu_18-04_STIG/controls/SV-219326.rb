control 'SV-219326' do
  title 'The Ubuntu operating system must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

Ubuntu operating systems need to track periods of inactivity and disable application identifiers after 35 days of inactivity.'
  desc 'check', 'Verify the account identifiers (individuals, groups, roles, and devices) are disabled after 35 days of inactivity with the following command:

Check the account inactivity value by performing the following command:

# sudo grep INACTIVE /etc/default/useradd

INACTIVE=35

If "INACTIVE" is not set to a value 0<[VALUE]<=35, or is commented out, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to disable account identifiers after 35 days of inactivity since the password expiration. 

Run the following command to change the configuration for adduser:

# sudo useradd -D -f 35

Note: DoD recommendation is 35 days, but a lower value is acceptable. The value "0" will disable the account immediately after the password expires.'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21051r305306_chk'
  tag severity: 'medium'
  tag gid: 'V-219326'
  tag rid: 'SV-219326r928521_rule'
  tag stig_id: 'UBTU-18-010445'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-21050r928520_fix'
  tag 'documentable'
  tag legacy: ['SV-109979', 'V-100875']
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end

control 'SV-252953' do
  title 'TOSS must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

Operating systems need to track periods of inactivity and disable application identifiers after 35 days of inactivity.'
  desc 'check', 'Verify the account identifiers (individuals, groups, roles, and devices) are disabled after 35 days of inactivity with the following command:

Check the account inactivity value by performing the following command:

$ sudo grep -i inactive /etc/default/useradd

INACTIVE=35

If "INACTIVE" is set to "-1", a value greater than "35", or is commented out, this is a finding.'
  desc 'fix', 'Configure TOSS to disable account identifiers after 35 days of inactivity after the password expiration. 

Run the following command to change the configuration for useradd:

$ sudo useradd -D -f 35

DoD recommendation is 35 days, but a lower value is acceptable. The value "-1" will disable this feature, and "0" will disable the account immediately after the password expires.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56406r824181_chk'
  tag severity: 'medium'
  tag gid: 'V-252953'
  tag rid: 'SV-252953r824183_rule'
  tag stig_id: 'TOSS-04-020120'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-56356r824182_fix'
  tag 'documentable'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end

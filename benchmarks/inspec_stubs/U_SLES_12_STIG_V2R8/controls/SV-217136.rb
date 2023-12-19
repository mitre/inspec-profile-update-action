control 'SV-217136' do
  title 'The SUSE operating system must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity after password expiration.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

The SUSE operating system needs to track periods of inactivity and disable application identifiers after 35 days of inactivity.'
  desc 'check', 'Verify the SUSE operating system disables account identifiers after "35" days of inactivity after the password expiration

Check the account inactivity value by performing the following command:

# sudo grep -i inactive /etc/default/useradd

INACTIVE=35

If "INACTIVE" is not set to a value greater than "0" and less than or equal to "35", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to disable account identifiers after "35" days of inactivity after the password expiration. 

Run the following command to change the configuration for "useradd" to disable the account identifier after "35" days:

# sudo useradd -D -f 35

DoD recommendation is "35" days, but a lower value greater than "0" is acceptable.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18364r369564_chk'
  tag severity: 'medium'
  tag gid: 'V-217136'
  tag rid: 'SV-217136r603262_rule'
  tag stig_id: 'SLES-12-010340'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-18362r369565_fix'
  tag 'documentable'
  tag legacy: ['V-77127', 'SV-91823']
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end

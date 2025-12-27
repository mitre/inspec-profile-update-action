control 'SV-221689' do
  title 'The Oracle Linux operating system must disable account identifiers (individuals, groups, roles, and devices) if the password expires.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

Operating systems need to track periods of inactivity and disable application identifiers after zero days of inactivity.'
  desc 'check', 'If passwords are not being used for authentication, this is Not Applicable.

Verify the operating system disables account identifiers (individuals, groups, roles, and devices) after the password expires with the following command:

# grep -i inactive /etc/default/useradd
INACTIVE=0

If the value is not set to "0", is commented out, or is not defined, this is a finding.'
  desc 'fix', 'Configure the operating system to disable account identifiers (individuals, groups, roles, and devices) after the password expires.

Add the following line to "/etc/default/useradd" (or modify the line to have the required value):

INACTIVE=0'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23404r419139_chk'
  tag severity: 'medium'
  tag gid: 'V-221689'
  tag rid: 'SV-221689r603260_rule'
  tag stig_id: 'OL07-00-010310'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-23393r419140_fix'
  tag 'documentable'
  tag legacy: ['V-99117', 'SV-108221']
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end

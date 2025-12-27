control 'SV-223723' do
  title 'The IBM RACF INACTIVE SETROPTS value must be set to 35 days.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

Operating systems need to track periods of inactivity and disable application identifiers after 35 days of inactivity.'
  desc 'check', 'From a z/OS command input screen enter:
List SETRopts

If the INACTIVE value is set properly In the message "INACTIVE USERIDS ARE BEING AUTOMATICALLY REVOKED AFTER xxx DAYS.", where xxx is a value "35" or less, this is not a finding.'
  desc 'fix', 'Configure the INACTIVE SETROPTS value to a value that is "35" or less. INACTIVE specifies the number of days that a USERID can remain unused and still be considered valid.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25396r514857_chk'
  tag severity: 'medium'
  tag gid: 'V-223723'
  tag rid: 'SV-223723r604139_rule'
  tag stig_id: 'RACF-ES-000760'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-25384r514858_fix'
  tag 'documentable'
  tag legacy: ['V-98153', 'SV-107257']
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end

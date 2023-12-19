control 'SV-248703' do
  title 'The OL 8 system-auth file must disable access to the system for account identifiers (individuals, groups, roles, and devices) with 35 days of inactivity.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. 
 
OL 8 needs to track periods of inactivity and disable application identifiers after 35 days of inactivity.'
  desc 'check', %q(Verify the account identifiers (individuals, groups, roles, and devices) are disabled after 35 days of inactivity by checking the account inactivity value with the following command: 
 
$ sudo grep 'inactive\|pam_unix' /etc/pam.d/system-auth | grep -w auth
 
auth      required      pam_lastlog.so inactive=35
auth      sufficient     pam_unix.so 

If the pam_lastlog.so module is listed below the pam_unix.so module in the "system-auth" file, this is a finding.

If the value of "inactive" is set to zero, a negative number, or is greater than 35, this is a finding.

If the line is commented out or missing, ask the administrator to indicate how the system disables access for account identifiers. If there is no evidence that the system is disabling access for account identifiers after 35 days of inactivity, this is a finding.)
  desc 'fix', 'Configure OL 8 to disable access to the system for account identifiers with 35 days of inactivity.  
 
Add/Modify the following line to "/etc/pam.d/system-auth" above the "pam_unix.so" statement: 

auth      required      pam_lastlog.so inactive=35

Note: The DoD recommendation is 35 days, but a lower value is acceptable.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52137r779673_chk'
  tag severity: 'medium'
  tag gid: 'V-248703'
  tag rid: 'SV-248703r779675_rule'
  tag stig_id: 'OL08-00-020260'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-52091r779674_fix'
  tag 'documentable'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end

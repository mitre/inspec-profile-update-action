control 'SV-100349' do
  title 'The SLES for vRealize must disable account identifiers of individuals and roles (such as root) after 35 days of inactivity after password expiration.'
  desc 'Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.

Operating systems need to track periods of inactivity and disable application identifiers after 35 days of inactivity.'
  desc 'check', 'Verify the SLES for vRealize disables account identifiers after "35" days of inactivity after the password expiration, by performing the following commands:

# grep "INACTIVE" /etc/default/useradd

The output must indicate the "INACTIVE" configuration option is set to an appropriate integer as shown in the example below: 

grep "INACTIVE" /etc/default/useradd
INACTIVE=35

If "INACTIVE" is not set to the value of "35" or less, this is a finding.'
  desc 'fix', 'Configure the SLES for vRealize to disable account identifiers after 35 days of inactivity after the password expiration. Run the following command to change the configuration for useradd:

Replace [VALUE] in the command with any integer from the range 0<[VALUE]<= 35.
# sed -i "s/^.*\\bINACTIVE\\b.*$/INACTIVE=[VALUE]/" /etc/default/useradd

DoD recommendation is "35" days, but a lower value is acceptable. The value "-1" will disable this feature and "0" will disable the account immediately after the password expires.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89391r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89699'
  tag rid: 'SV-100349r1_rule'
  tag stig_id: 'VRAU-SL-000725'
  tag gtitle: 'SRG-OS-000118-GPOS-00060'
  tag fix_id: 'F-96441r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end

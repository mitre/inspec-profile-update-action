control 'SV-239499' do
  title 'SLES for vRealize must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If SLES for vRealize does not limit the lifetime of passwords and force users to change their passwords, there is the risk that SLES for vRealize passwords could be compromised.'
  desc 'check', 'To check that SLES for vRealize enforces a "60" days or less maximum password age, run the following command:

# grep PASS_MAX_DAYS /etc/login.defs | grep -v "#"

The DoD requirement is "60" days or less (Greater than zero, as zero days will lock the account immediately). 

If "PASS_MAX_DAYS" is not set to the required value, this is a finding.'
  desc 'fix', 'To configure SLES for vRealize to enforce a "60" day or less maximum password age, edit the file "/etc/login.defs" and add or correct the following line. Replace [DAYS] with the appropriate amount of days.

# sed -i "/^[^#]*PASS_MAX_DAYS/ c\\PASS_MAX_DAYS 60" /etc/login.defs

The DoD requirement is "60" days or less (Greater than zero, as zero days will lock the account immediately).'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42732r661946_chk'
  tag severity: 'medium'
  tag gid: 'V-239499'
  tag rid: 'SV-239499r661948_rule'
  tag stig_id: 'VROM-SL-000385'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-42691r661947_fix'
  tag 'documentable'
  tag legacy: ['SV-99119', 'V-88469']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end

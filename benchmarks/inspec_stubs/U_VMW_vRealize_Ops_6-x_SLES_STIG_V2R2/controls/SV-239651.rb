control 'SV-239651' do
  title 'The SLES for vRealize must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new accounts are created they do not have unnecessary access.'
  desc 'check', 'Check for the configured umask value in login.defs with the following command:

# grep UMASK /etc/login.defs

If the default umask is not "077", this a finding.

Note: If the default umask is "000" or allows for the creation of world-writable files this becomes a CAT I finding.'
  desc 'fix', 'To configure the correct UMASK setting run the following command:

# sed -i "/^[^#]*UMASK/ c\\UMASK 077" /etc/login.defs

NOTE: Setting "UMASK 077" will break upgrades and other possible functionality within the product. When making upgrades to the system, you will need to revert this UMASK setting to the default for the duration of upgrades and then re-apply.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42884r662402_chk'
  tag severity: 'medium'
  tag gid: 'V-239651'
  tag rid: 'SV-239651r662404_rule'
  tag stig_id: 'VROM-SL-001510'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-42843r662403_fix'
  tag 'documentable'
  tag legacy: ['SV-99423', 'V-88773']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

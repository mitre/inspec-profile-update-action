control 'SV-100529' do
  title 'The SLES for vRealize must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new accounts are created they do not have unnecessary access.'
  desc 'check', 'Check for the configured "umask" value in "login.defs" with the following command:

# grep UMASK /etc/login.defs

If the default "umask" is not "077", this a finding.

Note: If the default umask is "000" or allows for the creation of world-writable files this becomes a Severity Code I finding.'
  desc 'fix', 'To configure the correct UMASK setting run the following command:

# sed -i "/^[^#]*UMASK/ c\\UMASK 077" /etc/login.defs'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89571r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89879'
  tag rid: 'SV-100529r1_rule'
  tag stig_id: 'VRAU-SL-001535'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-96621r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

control 'SV-215187' do
  title 'AIX must provide the lock command to let users retain their session lock until users are reauthenticated.'
  desc 'All systems are vulnerable if terminals are left logged in and unattended. Leaving system terminals unsecure poses a potential security hazard. 

To lock the terminal, use the lock command.'
  desc 'check', 'Check the system to determine if "bos.rte.security" is installed: 

# lslpp -L bos.rte.security
Fileset                      Level  State  Type  Description (Uninstaller)
  ----------------------------------------------------------------------------
 bos.rte.security           7.2.1.1    C     F    Base Security Function

If the "bos.rte.security" fileset is not installed, this is a finding. 

Check if lock command exist using the following command:
# ls  /usr/bin/lock

The above command should display the following:
/usr/bin/lock

If the above command does not show that "/usr/bin/lock" exists, this is a finding.'
  desc 'fix', 'Install "bos.rte.security" fileset from the AIX DVD Volume 1 using the following command (assuming that the DVD device is mounted to /dev/cd0):

# installp -aXYgd /dev/cd0 -e /tmp/install.log bos.rte.security'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16385r294012_chk'
  tag severity: 'medium'
  tag gid: 'V-215187'
  tag rid: 'SV-215187r508663_rule'
  tag stig_id: 'AIX7-00-001028'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-16383r294013_fix'
  tag 'documentable'
  tag legacy: ['SV-101329', 'V-91229']
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end

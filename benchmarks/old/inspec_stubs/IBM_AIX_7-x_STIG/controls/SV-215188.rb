control 'SV-215188' do
  title 'AIX must provide xlock command in the CDE environment to let users retain their sessions lock until users are reauthenticated.'
  desc 'All systems are vulnerable if terminals are left logged in and unattended. Leaving system terminals unsecure poses a potential security hazard.

If the interface is AIXwindows (CDE), use the xlock command to lock the sessions.'
  desc 'check', 'If AIX CDE (X11) is not used, this is Not Applicable.

Check the system to determine if "X11.apps.clients" is installed: 
# lslpp -L X11.apps.clients

If the "X11.apps.clients" fileset is not installed, this is a finding. 

Check if "xlock" command exists using the following command:
# ls  /usr/bin/X11/xlock

The above command should display the following:
/usr/bin/X11/xlock

If the above command does not show that "/usr/bin/X11/xlock" exists, this is a finding.'
  desc 'fix', 'Install "X11.apps.clients" fileset from the AIX DVD Volume 1 using the following command (assuming that the DVD is mounted to/dev/cd0):

# installp -aXYgd /dev/cd0 -e /tmp/install.log X11.apps.clients'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16386r294015_chk'
  tag severity: 'medium'
  tag gid: 'V-215188'
  tag rid: 'SV-215188r508663_rule'
  tag stig_id: 'AIX7-00-001029'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-16384r294016_fix'
  tag 'documentable'
  tag legacy: ['SV-101331', 'V-91231']
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end

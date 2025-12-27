control 'SV-257259' do
  title 'OL 8 must terminate idle user sessions.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended.'
  desc 'check', 'Verify that OL 8 logs out sessions that are idle for 15 minutes with the following command:

     $ sudo grep -i ^StopIdleSessionSec /etc/systemd/logind.conf

     StopIdleSessionSec=900

If "StopIdleSessionSec" is not configured to 900 seconds, this is a finding.'
  desc 'fix', 'Configure OL 8 to log out idle sessions by editing the /etc/systemd/logind.conf file with the following line:

     StopIdleSessionSec=900

The "logind" service must be restarted for the changes to take effect. To restart the "logind" service, run the following command:

     $ sudo systemctl restart systemd-logind'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-60943r917917_chk'
  tag severity: 'medium'
  tag gid: 'V-257259'
  tag rid: 'SV-257259r917919_rule'
  tag stig_id: 'OL08-00-020035'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-60885r917918_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end

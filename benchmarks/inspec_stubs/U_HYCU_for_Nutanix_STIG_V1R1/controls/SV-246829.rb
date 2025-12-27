control 'SV-246829' do
  title 'The HYCU VM/server must be configured to disable SSH.'
  desc 'It is detrimental for applications to provide functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Examples of non-essential capabilities include but are not limited to software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

Remote access using SSH is not required for administration as all administrative tasks can be performed either through the web interface or local console. SSH must be disabled to limit exposure.'
  desc 'check', 'Verify the SSHD daemon has been disabled using the following command:
$ sudo systemctl status sshd

Loaded: loaded (/usr/lib/systemd/system/sshd.service; disabled)

Active: inactive (dead)

If the SSHD daemon is not disabled and inactive or is not documented and approved for use, this is a finding.'
  desc 'fix', 'Stop the SSHD daemon:
$ sudo systemctl stop sshd

Disable the SSHD daemon:
$ sudo systemctl disable sshd

Note: The service must be stopped before it can be disabled.'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50261r768149_chk'
  tag severity: 'medium'
  tag gid: 'V-246829'
  tag rid: 'SV-246829r790582_rule'
  tag stig_id: 'HYCU-AC-000011'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-50215r768150_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

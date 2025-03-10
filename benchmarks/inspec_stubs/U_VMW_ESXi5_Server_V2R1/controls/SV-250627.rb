control 'SV-250627' do
  title 'Inetd and xinetd must be disabled or removed if no network services utilizing them are enabled.'
  desc 'Unnecessary services should be disabled to decrease the attack surface of the system.'
  desc 'check', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required. As root, log in to the ESXi Shell and execute the following:
# egrep -v "^sshd|authd" /var/run/inetd.conf>

The above command filters for services other than sshd and/or authd. If any other services are found, ask the SA if the services are required (i.e., required by 3rd party software).

If services other than sshd and/or authd are found and cannot be accounted for, this is a finding.

Re-enable Lockdown Mode on the host.'
  desc 'fix', 'Temporarily disable Lockdown Mode and enable the ESXi Shell via the vSphere Client. Open the vSphere/VMware Infrastructure (VI) Client and log in with appropriate credentials. If connecting to vCenter Server, click on the desired host. Click the Configuration tab. Click Software, Security Profile, Services, Properties, ESXi Shell and Options, respectively. Start the ESXi Shell service, where/as required.

As root, log in to the ESXi Shell and edit the /var/run/inetd.conf file. Comment (do not remove) any service line entries that cannot be accounted for.

Re-enable Lockdown Mode on the host.'
  impact 0.7
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54062r798878_chk'
  tag severity: 'high'
  tag gid: 'V-250627'
  tag rid: 'SV-250627r798880_rule'
  tag stig_id: 'SRG-OS-000095-ESXI5'
  tag gtitle: 'SRG-OS-000095-VMM-000480'
  tag fix_id: 'F-54016r798879_fix'
  tag 'documentable'
  tag legacy: ['V-39386', 'SV-51244']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end

control 'SV-239078' do
  title 'The Photon operating system must have the sshd SyslogFacility set to "authpriv".'
  desc 'Automated monitoring of remote access sessions allows organizations to detect cyberattacks and ensure ongoing compliance with remote access policies by auditing connection activities.'
  desc 'check', 'At the command line, execute the following command:

# sshd -T|&grep -i SyslogFacility

Expected result:

syslogfacility AUTHPRIV

If there is no output or if the output does not match expected result, this is a finding.'
  desc 'fix', 'Open /etc/ssh/sshd_config with a text editor.

Ensure that the "SyslogFacility" line is uncommented and set to the following:

SyslogFacility AUTHPRIV

At the command line, execute the following command:

# service sshd reload'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42289r675040_chk'
  tag severity: 'medium'
  tag gid: 'V-239078'
  tag rid: 'SV-239078r675042_rule'
  tag stig_id: 'PHTN-67-000006'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-42248r675041_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end

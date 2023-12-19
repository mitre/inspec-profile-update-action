control 'SV-257239' do
  title 'The macOS system must require users to reauthenticate for privilege escalation when using the "sudo" command.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization. 

When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.

'
  desc 'check', 'Verify the macOS system requires reauthentication when using the "sudo" command to elevate privileges with the following command:

/usr/bin/sudo /usr/bin/grep -r "timestamp_timeout" /etc/sudoers*

/etc/sudoers:Defaults    timestamp_timeout=0 

If conflicting results are returned, this is a finding.

If "timestamp_timeout" is set to a negative number, is commented out, or no results are returned, this is a finding.'
  desc 'fix', 'Configure the macOS system to require reauthentication when using the "sudo" command by editing the "/etc/sudoers" file to contain the line:

Defaults timestamp_timeout=0'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60924r905348_chk'
  tag severity: 'medium'
  tag gid: 'V-257239'
  tag rid: 'SV-257239r905350_rule'
  tag stig_id: 'APPL-13-004022'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-60865r905349_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end

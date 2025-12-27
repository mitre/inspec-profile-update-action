control 'SV-239079' do
  title 'The Photon operating system must have sshd authentication logging enabled.'
  desc 'Automated monitoring of remote access sessions allows organizations to detect cyberattacks and ensure ongoing compliance with remote access policies by auditing connection activities.

Shipping sshd authentication events to syslog allows organizations to use their log aggregators to correlate forensic activities among multiple systems.'
  desc 'check', 'At the command line, execute the following command:

# grep "^authpriv" /etc/rsyslog.conf

Expected result:

authpriv.*   /var/log/audit/sshinfo.log

If the command does not return any output, this is a finding.'
  desc 'fix', 'Open /etc/rsyslog.conf with a text editor and locate the following line:

$IncludeConfig /etc/vmware-syslog/syslog.conf

Ensure that the following entry is put beneath the stated line and before the "# vmware services" line.

authpriv.*   /var/log/audit/sshinfo.log

If the following line is at the end of the file, it must be removed or commented out:

auth.*                       /var/log/auth.log

At the command line, execute the following command:

# systemctl restart syslog
# service sshd reload'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42290r675043_chk'
  tag severity: 'medium'
  tag gid: 'V-239079'
  tag rid: 'SV-239079r675045_rule'
  tag stig_id: 'PHTN-67-000007'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-42249r675044_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end

control 'SV-253056' do
  title 'TOSS must monitor remote access methods.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', %q(Verify that TOSS monitors all remote access methods.

Check that remote access methods are being logged by running the following command:

$ sudo grep -E '(auth.*|authpriv.*|daemon.*)' /etc/rsyslog.conf
auth.*;authpriv.*;daemon.* /var/log/secure

If any of "auth.*", "authpriv.*" or "daemon.*" are not configured to be logged, this is a finding.)
  desc 'fix', 'Configure TOSS to monitor all remote access methods by adding or updating the following lines to the "/etc/rsyslog.conf" file:

auth.*;authpriv.*;daemon.* /var/log/secure

The "rsyslog" service must be restarted for the changes to take effect. To restart the "rsyslog" service, run the following command:

$ sudo systemctl restart rsyslog.service'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56509r824838_chk'
  tag severity: 'medium'
  tag gid: 'V-253056'
  tag rid: 'SV-253056r824840_rule'
  tag stig_id: 'TOSS-04-040010'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-56459r824839_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end

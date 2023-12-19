control 'SV-248530' do
  title 'All OL 8 remote access methods must be monitored.'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated monitoring capabilities increase risk and make remote user access management difficult at best. 
 
Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 
 
Automated monitoring of remote access sessions allows organizations to detect cyberattacks and ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, such as Remote Desktop Protocol (RDP), on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', %q(Verify that OL 8 monitors all remote access methods.

Check that remote access methods are being logged by running the following command:

$ sudo grep -E '(auth.*|authpriv.*|daemon.*)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf

/etc/rsyslog.conf:auth.*;authpriv.*;daemon.* /var/log/secure

If "auth.*", "authpriv.*", or "daemon.*" are not configured to be logged, this is a finding.)
  desc 'fix', 'Configure OL 8 to monitor all remote access methods by installing rsyslog with the following command: 
 
$ sudo yum install rsyslog 
 
Add or update the following lines to the "/etc/rsyslog.conf" file: 
 
auth.*;authpriv.*;daemon.* /var/log/secure 
 
The "rsyslog" service must be restarted for the changes to take effect. To restart the "rsyslog" service, run the following command: 
 
$ sudo systemctl restart rsyslog.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51964r779154_chk'
  tag severity: 'medium'
  tag gid: 'V-248530'
  tag rid: 'SV-248530r779156_rule'
  tag stig_id: 'OL08-00-010070'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-51918r779155_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end

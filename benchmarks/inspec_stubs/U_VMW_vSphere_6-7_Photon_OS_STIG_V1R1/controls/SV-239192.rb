control 'SV-239192' do
  title 'The Photon operating system must ship vCenter SSO logs via rsyslog.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. Proper configuration of rsyslog ensures that information critical to forensic analysis of security events is available for future action without any manual offloading or cron jobs.

vCenter SSO logs do currently ship with rsyslog by default. The login information contained in the SSO logs is critical to capture for forensic and troubleshooting purposes.'
  desc 'check', 'At the command prompt, execute the following command:

# grep -v "^#" /etc/vmware-syslog/stig-services-sso.conf

Expected result:

input(type="imfile" File="/var/log/vmware/sso/ssoAdminServer.log"
Tag="ssoAdmin"
Severity="info"
Facility="local0")

input(type="imfile" File="/var/log/vmware/sso/vmware-identity-sts.log"
Tag="ssoIdentitySTS"
Severity="info"
Facility="local0")

input(type="imfile" File="/var/log/vmware/sso/websso.log"
Tag="ssoWeb"
Severity="info"
Facility="local0")

If the file does not exist, this is a finding.

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/vmware-syslog/stig-services-vami.conf with a text editor.

Create the file if it does not exist.

Set the contents of the file as follows:

input(type="imfile" File="/var/log/vmware/sso/ssoAdminServer.log"
Tag="ssoAdmin"
Severity="info"
Facility="local0")

input(type="imfile" File="/var/log/vmware/sso/vmware-identity-sts.log"
Tag="ssoIdentitySTS"
Severity="info"
Facility="local0")

input(type="imfile" File="/var/log/vmware/sso/websso.log"
Tag="ssoWeb"
Severity="info"
Facility="local0")'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42403r675382_chk'
  tag severity: 'medium'
  tag gid: 'V-239192'
  tag rid: 'SV-239192r675384_rule'
  tag stig_id: 'PHTN-67-000121'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42362r675383_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end

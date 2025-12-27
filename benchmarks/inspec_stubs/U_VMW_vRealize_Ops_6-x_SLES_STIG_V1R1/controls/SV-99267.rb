control 'SV-99267' do
  title 'The SLES for vRealize must reveal error messages only to authorized users.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the SLES for vRealize system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Check the permissions of the syslog configuration file(s):

# ls -lL /etc/syslog-ng/syslog-ng.conf

If the file is not group owned by "root", this is a finding.'
  desc 'fix', 'Change the group-owner of the "/etc/rsyslog.conf" file to "root":

# chgrp root /etc/syslog-ng/syslog-ng.conf'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88309r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88617'
  tag rid: 'SV-99267r1_rule'
  tag stig_id: 'VROM-SL-000835'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-95359r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end

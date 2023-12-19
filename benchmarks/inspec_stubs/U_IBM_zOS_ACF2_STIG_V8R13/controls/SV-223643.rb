control 'SV-223643' do
  title 'IBM z/OS UNIX Telnet Server Startup parameters must be properly specified to display the banner.'
  desc 'Display of a standardized and approved use notification before granting access to the publicly accessible operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.'
  desc 'check', 'From the ISPF Command Shell enter: 
OMVS
CD /etc
cat inetd.config

If "-h" is included on the otelnetd statement, this is a finding. ("-h" indicates that a banner will not be displayed.)'
  desc 'fix', 'Configure the otelnetd startup command in the inetd.conf file to not include "-h".'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25316r501066_chk'
  tag severity: 'medium'
  tag gid: 'V-223643'
  tag rid: 'SV-223643r864509_rule'
  tag stig_id: 'ACF2-UT-000050'
  tag gtitle: 'SRG-OS-000228-GPOS-00088'
  tag fix_id: 'F-25304r501067_fix'
  tag 'documentable'
  tag legacy: ['V-97991', 'SV-107095']
  tag cci: ['CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end
